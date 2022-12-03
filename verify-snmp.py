#! /usr/bin/python3

import socket
import sys

def make_snmp_BER(type_: int, data: bytes):
    assert type_ >= 0x00 and type_ <= 0xff
    assert len(data) < 256

    for d in data:
        assert d >= 0x00 and d <= 0xff

    return [ type_, len(data) ] + data

def make_snmp_integer(v: int):
    bytes_ = v.to_bytes(8, byteorder='big', signed=True)

    array = [x for x in bytes_]

    while len(array) > 1 and array[0] == 0:
        del array[0]

    return make_snmp_BER(0x02, array)

def make_snmp_octetstring(s: str):
    array = [ord(x) for x in s]

    return make_snmp_BER(0x04, array)

def make_snmp_null():
    return make_snmp_BER(0x05, [])

def make_snmp_oid(name):
    out = []

    if name[0:4] == '1.3.':
        out.append(43)

        name = name[4:]

    values = [int(v) for v in name.split('.')]

    for v in values:
        work = v

        b7 = []

        if work == 0:
            b7.append(0)

        use_bit = 128 if work > 127 else 0

        while work > 0:
            b7.insert(0, (work & 127))

            work >>= 7

        for i in range(0, len(b7) - 1):
            b7[i] |= 128

        out += b7

    return [0x06, len(out)] + out

def make_snmp_sequence(*inputs):
    combined = []

    for input_ in inputs:
        combined += input_

    return make_snmp_BER(0x30, combined)

def make_snmp_message(version, community, request):
    return make_snmp_sequence(make_snmp_integer(version), make_snmp_octetstring(community), request)

def make_snmp_get_request(version, community, oids):
    varbind_list = list()

    for o in oids:
        bin_oid = make_snmp_oid(o)

        varbind_list += make_snmp_sequence(bin_oid, make_snmp_null())

    return make_snmp_message(version, community, make_snmp_BER(0xa0, make_snmp_integer(1) + make_snmp_integer(0) + make_snmp_integer(0) + make_snmp_sequence(varbind_list)))

assert make_snmp_BER(0x030, [ 1, 2, 3, 4 ]) == [48, 4, 1, 2, 3, 4]
assert make_snmp_integer(-123) == [2, 8, 255, 255, 255, 255, 255, 255, 255, 133]
assert make_snmp_integer(131071) == [2, 3, 1, 255, 255]
assert make_snmp_octetstring('test 1234') == [4, 9, 116, 101, 115, 116, 32, 49, 50, 51, 52]
assert make_snmp_null() == [5, 0]
assert make_snmp_message(1, 'public', make_snmp_null()) == [48, 13, 2, 1, 1, 4, 6, 112, 117, 98, 108, 105, 99, 5, 0]
assert make_snmp_oid('1.3.6.1.4.1.2680.1.2.7.3.2.0') == [6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0]
assert make_snmp_get_request(0, 'private', ['1.3.6.1.4.1.2680.1.2.7.3.2.0']) == [48, 44, 2, 1, 0, 4, 7, 112, 114, 105, 118, 97, 116, 101, 160, 30, 2, 1, 1, 2, 1, 0, 2, 1, 0, 48, 19, 48, 17, 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0, 5, 0]

def get_snmp_integer(data, offset):
    if data[offset] != 0x02:
        print(f'Expected integer at {offset}, got type 0x{data[offset]:02x}')

    if data[offset + 1] + 2 > len(data):
        print(f'Field length wrong: {data[offset + 1] + 2} does not fit in {len(data)} at offset {offset}')

    v = 0

    for i in range(0, data[offset + 1]):
        v <<= 8
        v |= data[offset + 2]

    return (v, data[offset + 1] + 2)

target = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

request = bytearray(make_snmp_get_request(0, 'public', ['1.3.6.1.4.1.2680.1.2.7.3.2.0', '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.4.57850.1.11.1']))

s.sendto(request, (target, 161))

reply = s.recvmsg(1600)
payload = reply[0]

# verify total length
if payload[1] + 2 > len(payload):
    print('Total message size incorrect')

offset = 2

# verify version
rc = get_snmp_integer(payload, offset)
offset += rc[1]

if rc[0] != 0:
    print(f'SNMP version unexpected ({rc[0]})')

# verify community
rc = get_snmp_octetstring(payload, offset)
offset += rc[1]

c = rc[0].decode('ascii')
if c != 'public':
    print(f'Community unexpected ({c})')

s.close()
