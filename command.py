from __future__ import print_function

import inotify.adapters
import inotify.constants
import os
import struct
import subprocess

class Command:
    SHELL = 0   # Executes a command in a shell, recording its return value, stdout and stderr
    WATCH = 1   # Waits for the creation of a path, then reads and return its contents as a bytes object
    END   = 255 # Signals that the client is finished sending commands

    def to_bytes(self):
        raise NotImplementedError

    @staticmethod
    def from_bytes(bytes):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError

class ShellCommand(Command):

    class Result:
        def __init__(self, retcode, out, err):
            self.type = Command.SHELL
            self.retcode = retcode
            self.stdout = out
            self.stderr = err

        def __str__(self):
            return "exit code: {}\nstdout: {}\nstderr: {}".format(self.retcode, self.stdout, self.stderr)

        def to_bytes(self):
            buf = bytearray()
            buf.append(self.type)
            buf.extend(struct.pack(">i", self.retcode))

            buf.extend(struct.pack(">H", len(self.stdout)))
            if self.stdout:
                buf.extend(self.stdout)

            buf.extend(struct.pack(">H", len(self.stderr)))
            if self.stderr:
                buf.extend(self.stderr)

            return bytes(buf)

        @staticmethod
        def from_bytes(buf):
            retcode = struct.unpack(">i", buf[1:5])[0]

            outlen = struct.unpack(">H", buf[5:7])[0]
            out = str(buf[7:7+outlen]) if outlen else None

            errlen = struct.unpack(">H", buf[7+outlen:7+outlen+2])[0]
            err = str(buf[7+outlen:]) if errlen else None

            return ShellCommand.Result(retcode, out, err)

    # command is the command to execute
    def __init__(self, cmd):
        self.type = Command.SHELL
        self.command = cmd

    def __str__(self):
        return "Command type: SHELL; command: {}".format(self.command)

    def to_bytes(self):
        # can't easily serialise strings, so we're doing it the old-fashioned way...
        buf = bytearray()
        buf.append(self.type)
        buf.append(len(self.command))
        buf.extend(self.command)
        return bytes(buf)

    @staticmethod
    def from_bytes(buf):
        cmdlenbyte = buf[1]
        if isinstance(cmdlenbyte, int):
            cmdlen = cmdlenbyte
        else:
            cmdlen = ord(cmdlenbyte)

        command = str(buf[2:2+cmdlen])
        return ShellCommand(command)

    def run(self):
        p = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        return ShellCommand.Result(p.returncode, out, err)


class WatchCommand(Command):

    class Result:
        def __init__(self, contents, err):
            self.type = Command.WATCH
            self.contents = contents if contents else ""

            if err and len(err) > 255:
                self.err = err[:256]
            else:
                self.err = err

        def __str__(self):
            return self.contents

        def to_bytes(self):
            buf = bytearray()
            buf.append(self.type)

            buf.extend(struct.pack(">I", len(self.contents) if self.contents else 0))
            if self.contents:
                buf.extend(self.contents)

            buf.append(len(self.err) if self.err else 0)
            if self.err:
                buf.extend(self.err)

            return bytes(buf)

        @staticmethod
        def from_bytes(buf):
            contentlen = struct.unpack(">I", buf[1:5])[0]
            contents = bytes(buf[5:5+contentlen]) if contentlen else None

            # bytearrays store ints, "bytes" is an alias for str
            errlenbyte = buf[5+contentlen]
            if isinstance(errlenbyte, int):
                errlen = errlenbyte
            else:
                errlen = ord(errlenbyte)

            err = str(buf[5+contentlen:]) if errlen else None

            return WatchCommand.Result(contents, err)

    # path is the path to the file for the creation of which to watch
    def __init__(self, path):
        self.type = Command.WATCH
        self.path = path

    def __str__(self):
        return "Command type: WATCH; path to watch: {}".format(self.path)

    def to_bytes(self):
        buf = bytearray()
        buf.append(self.type)
        buf.append(len(self.path))
        buf.extend(self.path)
        return bytes(buf)

    @staticmethod
    def from_bytes(buf):
        pathlen = buf[1] if isinstance(pathlen, int) else ord(buf[1])
        path = str(buf[2:2+pathlen])
        return WatchCommand(path)

    def run(self):
        watchdir, watchfile = os.path.split(self.path)
        if not os.path.exists(watchdir):
            err = "No such directory {}".format(watchdir)
            return WatchCommand.Result(None, err)

        try:
            i = inotify.adapters.Inotify(block_duration_s = -1) # -1 makes epoll block indefinitely
            i.add_watch(watchdir, mask=inotify.constants.IN_CLOSE_WRITE)
            for event in i.event_gen():
                if event:
                    (header, type_names, watch_path, filename) = event
                    if filename == watchfile:
                        break

            with open(self.path, 'r') as payload:
                contents = payload.read()
                result = WatchCommand.Result(contents, None)

        except Exception, err:
            print("Error while watching file:")
            print(err)
            print("This error will be transmitted to the client.")
            result = WatchCommand.Result(None, str(err))
        finally:
            i.remove_watch(self.path)

        return result

class EndCommand(Command):

    def __init__(self):
        pass

    def __str__(self):
        return "Command type: END"

    def to_bytes(self):
        return bytes(b'\xff')

    @staticmethod
    def from_bytes(buf):
        return EndCommand()

    def run(self):
        print("This is the end, beautiful friend")
