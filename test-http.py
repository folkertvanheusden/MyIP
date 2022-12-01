#! /usr/bin/python3

import random
import socket

def gen_url(relative):
    assert relative  # absolute not implemented yet TODO

    url = ''

    if random.choice([False, True]):
        for i in range(0, 10):
            url += '\\' if random.choice([False, True]) else '/'

    for i in range(0, 128):
        c = random.randint(0, 256)

        url += f'%{c:02x}' if (c < 32 or c > 126) and random.choice([False, True]) else chr(c)

    return url

def gen_http_prot():
    if random.choice([False, True]):
        return f'HTTP/{random.randint(0, 10)}.{random.randint(0, 10)}'

    return f'HTTP/{random.randint(0, 10)}'

def gen_eol():
    return random.choices(['\r\n', '\n', '\r', '\n\r', '', ' '],
                          weights=[50    , 10  , 10  , 10    , 10, 10 ])[0]

def gen_space():
    if random.choices([False, True], weights=[90, 10]):
        return ''

    return random.choices([' ', '\t'], weights=[80, 20])[0] * random.randint(1, 3)

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect(('192.168.3.2', 80))

    request = ''

    for i in range(0, 100):
        if i == 0:
            method = random.choice(['GET', 'POST', 'HEAD'])
            sp1    = gen_space()
            sp2    = gen_space()
            url    = gen_url(True)
            prot   = gen_http_prot()
            eol    = gen_eol()

            request += f'{method}{sp1}{url}{sp2}{prot}{eol}'

        else:
            pass  # TODO: k/v pairs

    request += gen_eol()

    s.send(request.encode('ascii', 'ignore'))

    s.close()
