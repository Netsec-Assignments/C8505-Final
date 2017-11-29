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

    def run(self, result_queue):
        """Runs the command.
        
        Positional arguments:
        result_queue - A queue to which Result objects for this command will be pushed.
                       Actual commands may continue to run indefinitely and push results
                       and should document this.
        """
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
            buf.extend(struct.pack("<i", self.retcode))

            buf.extend(struct.pack("<H", len(self.stdout)))
            if self.stdout:
                buf.extend(self.stdout)

            buf.extend(struct.pack("<H", len(self.stderr)))
            if self.stderr:
                buf.extend(self.stderr)

            return bytes(buf)

        @staticmethod
        def from_bytes(buf):
            offset = 1

            retcode = struct.unpack("<i", buf[offset:offset+4])[0]
            offset += 4

            outlen = struct.unpack("<H", buf[offset:offset+2])[0]
            offset += 2

            out = str(buf[offset:offset+outlen]) if outlen else None
            offset += outlen

            errlen = struct.unpack("<H", buf[offset:offset+2])[0]
            offset += errlen

            err = str(buf[offset:]) if errlen else None

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

    def run(self, result_queue):
        p = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        result = ShellCommand.Result(p.returncode, out, err)
        result_queue.put(result)


class WatchCommand(Command):
    DIR  = 0
    FILE = 1

    class Result:
        def __init__(self, path, contents, err):
            self.type = Command.WATCH
            self.path = path
            self.contents = contents if contents else ""
            self.err = err

        def __str__(self):
            result = "Path: {}\n".format(self.path)
            if self.err:
                result += "Error: {}".format(self.err)
            else:
                result += "Contents: {}".format(self.contents)

        def to_bytes(self):
            buf = bytearray()
            buf.append(self.type)

            # Add the full path of the file whose contents or error are stored
            # in this result
            buf.extend(struct.pack("<H", len(self.path)))
            buf.extend(self.path)
    
            buf.extend(struct.pack("<I", len(self.contents) if self.contents else 0))
            if self.contents:
                buf.extend(self.contents)

            buf.append(len(self.err) if self.err else 0)
            if self.err:
                buf.extend(self.err)

            return bytes(buf)

        @staticmethod
        def from_bytes(buf):
            offset = 1

            pathlen = struct.unpack("<H", buf[offset:offset+2])[0]
            offset += 2
            path = str(buf[offset:offset+pathlen])
            offset += pathlen

            contentlen = struct.unpack("<I", buf[offset:offset+4])[0]
            offset += 4
            contents = bytes(buf[offset:offset+contentlen]) if contentlen else None
            offset += contentlen

            # bytearrays store ints, "bytes" is an alias for str
            errlenbyte = buf[5+contentlen]
            if isinstance(errlenbyte, int):
                errlen = errlenbyte
            else:
                errlen = ord(errlenbyte)

            err = str(buf[offset:]) if errlen else None

            return WatchCommand.Result(path, contents, err)

    def __init__(self, path, path_type):
        """Creates a watch command, which watches a directory or file for changes and reports changed files' contents.

        Positional arguments:
        path      - The path to watch. If this is a directory, it must already
                    exist. If it is a file, its enclosing directory must exist.
                    Length must be <= 1024 bytes.
        path_type - The type of path; must be one of WatchCommand.DIR or
                    WatchCommand.FILE.
        """

        assert(path_type == WatchCommand.DIR or path_type == WatchCommand.FILE)

        self.type = Command.WATCH
        self.path = path
        self.path_type = path_type

    def __str__(self):
        return "Command type: WATCH; path to watch: {}; path type: {}".format(self.path, "directory" if self.path_type == WatchCommand.DIR else "file")

    def to_bytes(self):
        buf = bytearray()
        buf.append(self.type)
        buf.extend(struct.pack("<H", len(self.path)))
        buf.extend(self.path)
        buf.append(self.path_type)
        return bytes(buf)

    @staticmethod
    def from_bytes(buf):
        pathlen = struct.unpack("<H", buf[1:3])[0]
        path = str(buf[3:3+pathlen])
        path_type = ord(buf[3+pathlen])
        return WatchCommand(path, path_type)

    def run(self, result_queue):
        if self.path_type == WatchCommand.FILE:
            watchdir, watchfile = os.path.split(self.path)
        else:
            watchdir = self.path

        if not os.path.isdir(watchdir):
            err = "No such directory {}".format(watchdir)
            return WatchCommand.Result(None, err)

        try:
            i = inotify.adapters.Inotify(block_duration_s = -1) # -1 makes epoll block indefinitely
            i.add_watch(watchdir, mask=inotify.constants.IN_CLOSE_WRITE)
            for event in i.event_gen():
                if event:
                    (header, type_names, watch_path, filename) = event
                    if self.path_type == WatchCommand.FILE and filename != watchfile:
                        continue

                    fullpath = os.path.join(watchdir, filename)
                    print("{} was modified. New contents will be sent to client.".format(fullpath))

                    with open(watch_path, 'r') as payload:
                        contents = payload.read()
                        result = WatchCommand.Result(fullpath, contents, None)
                        result_queue.put(result)

        except Exception, err:
            print("Error while watching {}:".format("file" if self.path_type == WatchCommand.FILE else "directory"))
            print(err)
            print("This error will be transmitted to the client.")
            result = WatchCommand.Result(self.path, None, str(err))
            result_queue.put(result)
        finally:
            i.remove_watch(self.path)

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

    def run(self, result_queue):
        print("This is the end, beautiful friend")
