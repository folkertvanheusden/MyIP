#! /usr/bin/python3

import json
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.3.2', 55201))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

def recv_reply(s: socket) -> str:
    reply = ''

    while True:
        c = s.recv(1).decode('ascii')

        if c == '\n':
            break

        reply += c

    return reply

while True:
    bs = 512

    block = bytearray(bs)

    command = { "mode": "receive", "block_size": bs }
    s.send(json.dumps(command).encode('ascii'))
    s.send('\n'.encode('ascii'))

    print(recv_reply(s))

    s.send(block)

    print(recv_reply(s))

    break
