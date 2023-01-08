#! /usr/bin/python3

import socket
import sys

class myipud:
    def __init__(self, location):
        self.buffer = ''

        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            self.s.connect(location)

        except FileNotFoundError as e:
            print(f'Socket cannot be opened ({e}), is MyIP running?')
            sys.exit(0)

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

def help():
    print(' * sessions')
    print(' * list-devices  list the physical devices, to be used with start/stop-pcap')
    print(' * start-pcap x  start pcap recording on device x')
    print(' * stop-pcap x   stop pcap recording on device x')

if len(sys.argv) == 1:
    help()
    sys.exit(1)

mi = myipud('/tmp/myipstats.sock')

if sys.argv[1] == 'sessions':
    print(mi.request('sessions'))

elif sys.argv[1] == 'list-devices':
    print(mi.request('list-devices'))

elif sys.argv[1] == 'start-pcap':
    print(mi.request('start-pcap|%s' % sys.argv[2]))

elif sys.argv[1] == 'stop-pcap':
    print(mi.request('stop-pcap|%s' % sys.argv[2]))

else:
    help();
