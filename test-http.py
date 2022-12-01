#! /usr/bin/python3

import random
import socket

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

def gen_space():
    if random.choices([False, True], weights=[90, 10])[0]:
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


    print(request)

    s.send(request.encode('ascii', 'ignore'))

    s.close()
