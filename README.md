# Dependencies
Note: these can all be installed via pip (and probably easy_install etc.).
* [scapy](http://www.secdev.org/projects/scapy/)
* [inotify](https://pypi.python.org/pypi/inotify)
* [pycrypto](https://pypi.python.org/pypi/pycrypto)
* [setproctitle](https://pypi.python.org/pypi/setproctitle)

# Running the Programs
First, install the dependencies above using your Python 2 package manager of choice.

To run the backdoor server:

```
python main.py server listen port client port [-m process name] [-p password] [-k aes key]
```

where
* ```server``` is the literal string server
* ```listen port``` is the port on which the server will listen for backdoor client connections (1-65535 inclusive)
* ```client port``` is the port to which the server will send the client's results (1-65535 inclusive)
* ```process name``` will replace the backdoor server's process name so that it's harder to find
* ```password``` is a password added to packets so that the server can tell if a packet bound for the listen port is a client trying to connect and so that the client and server can ensure that packets were properly decrypted
* ```aes key``` is the key to use for AES encryption (applied to all packets except the initial client connection)

To run the backdoor client:

```
python main.py client listen port server port -s server host [-p password] [-k aes key]
```

where
* ```client``` is the literal string client
* ```listen port``` is the port on which the client will listen for backdoor server command results (1-65535 inclusive)
* ```server port``` is the port on which the server will listen for client connections (1-65535 inclusive)
* ```server host``` is the backdoor server's host name or IP (mandatory when the program is used in client mode even though it's technically "optional")
* ```password``` and ```aes key```: same as the server documentation above

The client will continuously prompt for commands, send them to the server, and display their results. To exit the prompt, type ```Ctrl+D``` or ```Ctrl+C```.
