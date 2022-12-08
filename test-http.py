#! /usr/bin/python3

import random
import socket
import string

def weighted_rand_0_10():
    return random.choices([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], weights=[10, 9, 8, 7, 6, 5, 4, 3, 2, 1])[0]

def gen_url(relative):
    assert relative  # absolute not implemented yet TODO

    url = ''

    if random.choice([False, True]):
        for i in range(0, weighted_rand_0_10()):
            url += '\\' if random.choices([False, True], weights=[90, 10])[0] else '/'

    for i in range(0, 32):
        c = random.choices([random.randint(0, 33), random.randint(33, 127), random.randint(127, 256)], weights=[5, 95, 5])[0]

        url += f'%{c:02x}' if (c < 32 or c > 126) and random.choices([False, True], weights=[5, 95])[0] else chr(c)

    if random.choice([False, True]):
        url += '.' + random.choice(['html', 'htm', 'php', 'php3', 'cgi', 'jpg', 'jpeg', 'png'])

    return url

def gen_http_prot():

    if random.choices([False, True], weights=[10, 90])[0]:
        return f'HTTP/{weighted_rand_0_10()}.{weighted_rand_0_10()}'

    return f'HTTP/{weighted_rand_0_10()}'

def gen_eol():
    return random.choices(['\r\n', '\n', '\r', '\n\r', '', ' '],
                          weights=[50    , 10  , 10  , 10    , 10, 10 ])[0]

def gen_space(swap_w):
    if random.choices([False, True], weights=([90, 10] if swap_w else [10, 90]))[0]:
        return ''

    return random.choices([' ', '\t'], weights=[80, 20])[0] * random.randint(1, 3)

def gen_ascii():
    a = ''

    for i in range(1, 128):
        a += random.choice(string.ascii_letters)

    return a

while True:
    request = ''

    for i in range(0, 100):
        if i == 0:
            method = random.choice(['GET', 'POST', 'HEAD'])
            sp1    = gen_space(True)
            sp2    = gen_space(True)
            url    = gen_url(True)
            prot   = gen_http_prot()
            eol    = gen_eol()

            request += f'{method}{sp1}{url}{sp2}{prot}{eol}'

        else:
            k      = gen_ascii() if random.choices([False, True], weights=[10, 90])[0] else ''
            v      = gen_ascii() if random.choices([False, True], weights=[10, 90])[0] else ''
            colon  = ':' if random.choices([False, True], weights=[10, 90])[0] else ''
            sp1    = gen_space(False)
            sp2    = gen_space(False)
            eol    = gen_eol()

            request += f'{k}{sp1}{colon}{sp2}{v}{eol}'

    request += gen_eol()

    # TODO: casing fuzzer

    print(request)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(5.0)

        s.connect(('192.168.3.2', 80))

        b = request.encode('ascii', 'ignore')

        if random.choices([False, True], weights=[10, 90])[0]:
            s.send(request.encode('ascii', 'ignore'))

        elif len(b) > 0:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)

            while True:
                b_len = len(b)
            
                if b_len == 0:
                    break

                cur_len = random.randint(1, b_len + 1)

                s.send(b[0:cur_len])

                b = b[cur_len:]

        s.close()

    except OSError as oe:
        print(f' *** Timeout: {oe} ***')
