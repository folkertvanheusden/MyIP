#! /usr/bin/python3

import random
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    n = random.randint(1, 1500)

    out = bytes([random.getrandbits(8) for _ in range(0, n)])

    s.sendto(out, ('myip.vanheusden.com', 161))
