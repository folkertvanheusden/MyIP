#! /usr/bin/python3

import random
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def get_random_bytes(n):
    return bytes([random.getrandbits(8) for _ in range(0, n)])

def append(a, b):
    for by in b:
        a.append(by)

    return a

def get_msg(max_len):
    if max_len < 2:
        return bytearray()

    msg = bytearray()

    msg.append(get_random_bytes(1)[0])  # identifier

    len_ = random.randrange(0, max_len)
    msg = append(msg, len_.to_bytes(1, 'big'))

    msg = append(msg, get_random_bytes(len_))

    return msg

def req_msg(max_len):
    if max_len < 2:
        return bytearray()

    n = random.randrange(0, 8)

    msg = bytearray()
    msg.append(0x30)
    msg.append(255)  # to be adjusted

    len_ = 0

    for i in range(0, n):
        if random.randrange(0, 3) == 0:
            curm = req_msg(max_len - len_ - 2)

            len_ += len(curm)
            msg = append(msg, curm)

        else:
            curm = get_msg(max_len - len_ - 2)

            len_ += len(curm)
            msg = append(msg, curm)

        if len_ == max_len - 2:
            break

    msg[1] = (len_.to_bytes(1, 'big'))[0]

    return msg

while True:
    sel = random.getrandbits(1)

    if sel == 0:  # invalid length
        msg = get_random_bytes(random.randrange(1, 1500))

    elif sel == 1:  # sequence
        msg = req_msg(255)

    s.sendto(msg, (sys.argv[1], 161))
