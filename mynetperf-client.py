#! /usr/bin/python3

import getopt
import json
import math
import socket
import sys
import time


host = '192.168.3.2'
port = 55201

mode = None

n_todo = None

json_results = False

work_bs = 65536

opts, args = getopt.getopt(sys.argv[1:], 'H:p:b:m:n:jh')

for o, a in opts:
    if o == '-H':
        host = a

    elif o == '-p':
        port = int(a)

    elif o == '-b':
        work_bs = int(a)

    elif o == '-m':
        mode = True if a == 'send' else False

    elif o == '-n':
        n_todo = int(a)

    elif o == '-j':
        json_results = True

    elif o == '-h':
        print('-H x   host')
        print('-p x   port (default: 55201)')
        print('-b x   block size (default: %d)' % work_bs)
        print('-m x   mode: send or receive')
        print('-n x   limit to x exchanges')
        print('-j     only print results in json format')
        sys.exit(0)

if not json_results:
    print('send mode' if mode else 'receive mode')

work = bytearray(work_bs)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
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

try:
    if mode:
        while n_todo is None or n < n_todo:
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

            if not json_results:
                print(j, f"{math.floor(speed)} kB/s")

    else:
        while n_todo is None or n < n_todo:
            command = { "mode": "send", "block_size": work_bs }
            s.send(json.dumps(command).encode('ascii'))
            s.send('\n'.encode('ascii'))

            if json.loads(recv_reply(s))['result'] != 'ok':
                break

            start_ts = time.time()

            bs = work_bs

            while bs > 0:
                bs -= len(s.recv(bs))

            end_ts = time.time()

            j = json.loads(recv_reply(s))

            took = end_ts - start_ts

            speed = work_bs / (took * 1024)

            median.append(speed)

            total += speed
            n += 1

            min_speed = min(min_speed, speed)
            max_speed = max(max_speed, speed)

            if not json_results:
                print(f"{math.floor(speed)} kB/s")


except KeyboardInterrupt as ki:
    pass

if not json_results:
    print()

if n > 0:
    median.sort()

    median_val = median[n // 2] if (n & 1) else (median[n // 2] + median[n // 2 + 1]) / 2

    if json_results:
        results = {
                'n': n,
                'average': total / n * 1024,
                'median': median_val * 1024,
                'min': min_speed * 1024,
                'max': max_speed * 1024,
                'units': 'bytes',
                'block-size': work_bs
                }

        print(json.dumps(results))

    else:
        print(f"{n} transfers, average: {total/n:.3f} kB/s, median: {median_val:.3f} kB/s, minimum: {min_speed:.0f} kB/s, maximum: {max_speed:.0f} kB/s")
