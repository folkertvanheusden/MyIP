#! /usr/bin/python3

import json
import math
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

min_speed = math.inf
max_speed = -math.inf
n = 0
total = 0
median = []

work = bytearray(131072)

work_bs = 65536

try:
    while True:
        bs = work_bs

        command = { "mode": "receive", "block_size": bs }
        s.send(json.dumps(command).encode('ascii'))
        s.send('\n'.encode('ascii'))

        if json.loads(recv_reply(s))['result'] != 'ok':
            break

        while bs > 0:
            cur_bs = min(bs, len(work))

            s.send(work[0:cur_bs])

            bs -= cur_bs

        j = json.loads(recv_reply(s))

        speed = work_bs * 1000000 / j['took'] / 1024

        median.append(speed)

        total += speed
        n += 1

        min_speed = min(min_speed, speed)
        max_speed = max(max_speed, speed)

        print(j, f"{math.floor(speed)} kB/s")

except KeyboardInterrupt as ki:
    pass

median.sort()

median_val = median[n // 2] if (n & 1) else (median[n // 2] + median[n // 2 + 1]) / 2

print(f"{n} transfers, average: {total/n:.3f} kB/s, median: {median_val:.3f} kB/s, minimum: {min_speed:.0f} kB/s, maximum: {max_speed:.0f} kB/s")
