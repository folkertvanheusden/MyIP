#! /usr/bin/python3

import socket

class myipud:
    def __init__(self, location):
        self.buffer = ''

        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.s.connect(location)

    def request(self, req):
        req_b = (req + '\n').encode('ascii')

        self.s.send(req_b)

        while True:
            lf = self.buffer.find('\n')

            if lf != -1:
                rc = self.buffer[0:lf]

                self.buffer = self.buffer[lf + 1:]

                return rc

            data = self.s.recv(4096)

            if len(data) == 0:
                rc = self.buffer
                self.buffer = ''
                return rc

            self.buffer += data.decode('ascii')

mi = myipud('/tmp/myipstats.sock')

print(mi.request('sessions'))

print(mi.request('list-devices'))
