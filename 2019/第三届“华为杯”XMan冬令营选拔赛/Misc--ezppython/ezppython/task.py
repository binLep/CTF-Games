import random
import string
import SocketServer
from hashlib import sha256
import re
from flag import flag

the_key_to_flag = "flag?!@#"


class Task(SocketServer.BaseRequestHandler):
    def handle(self):
        req = self.request
        try:
            req.sendall("Give me key:")
            s = req.recv(6666).strip()
            if len(set(s)) > 7:
                req.sendall("bye~")
            elif re.match("\d|ord|exec|chr|all|var|flag", s):
                req.sendall("Too young!")
            else:
                val = eval(s)
                if val == the_key_to_flag:
                    req.sendall("Congratulations! Here is your flag: %s" % flag)
                else:
                    req.sendall("bye~")
        except:
            req.sendall("No magic")


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 23333
    print 'Run in port:23333'
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
