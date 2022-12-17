#! /usr/bin/python3

from snmp_client import snmp_client
import socket
import sys

target = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

request = bytearray(snmp_client.make_snmp_get_request(0, 'public', ['1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0']))

s.sendto(request, (target, 161))

reply = s.recvmsg(1600)
payload = reply[0]

# verify total length
if payload[1] + 2 > len(payload):
    print('Total message size incorrect')

offset = 2

# verify version
rc = snmp_client.get_snmp_integer(payload, offset)
offset += rc[1]

if rc[0] != 0:
    print(f'SNMP version unexpected ({rc[0]})')

# verify community
rc = snmp_client.get_snmp_octetstring(payload, offset)
offset += rc[1]

c = rc[0].decode('ascii')
if c != 'public':
    print(f'Community unexpected ({c})')

rc = snmp_client.get_pdu(payload, offset)
offset += rc[1]
print(rc)

s.close()
