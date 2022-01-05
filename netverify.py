#! /usr/bin/python3

# (C) 2021 by Folkert van Heusden <mail@vanheusden.com>
# Licensed under the Apache License v2.0

import copy
import socket

port_tcp_listening = 13  # 'daytime' service
port_tcp_not_listening = 29889  # should trigger 'connection refused'

def checksum(data):
    chksum = 0

    for idx in range(0, len(data), 2):
        word = (data[idx] << 8) | data[idx + 1]

        chksum += word

    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += (chksum >> 16)
    chksum = (~chksum) & 0xffff

    return chksum

def mac_to_str(mac):
    return f'{mac[0]:02x} {mac[1]:02x} {mac[2]:02x} {mac[3]:02x} {mac[4]:02x} {mac[5]:02x}'

def ipv4_addr_to_str(addr):
    return f'{addr[0]}.{addr[1]}.{addr[2]}.{addr[3]}'

def get_uint16(data):
    return (data[0] << 8) | data[1]

def get_uint32(data):
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]

def open_netdev(dev_name):
    fd = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as sock:

    fd.bind((dev_name, 0))

    return fd

fd = open_netdev('myip')

while True:
    raw_packet = bytearray(sock.recv(9000))

    if len(raw_packet) & 1:
        raw_packet += bytearray([ 0 ])

    packet_type = get_uint16(raw_packet[12:14])

    print(f'from: {mac_to_str(raw_packet[0:6])} to: {mac_to_str(raw_packet[6:12])} type: {packet_type:04x}')

    payload = raw_packet[14:]

    if packet_type == 0x0800:  # IPv4
        version = payload[0] >> 4
        if version != 4:
            print('Mismatch between Ethertype and IP-header version field for IPv4 packet')

        ihl = payload[0] & 0x0f

        if ihl < 5:
            print(f'IPv4 header too short, must be at least 20 (5 fields): {ihl}')

        ip_header = payload[0: ihl * 4]  # TODO: check size

        # verify header checksum
        ipv4_checksum = get_uint16(payload[10:12])

        ip_header_copy = copy.deepcopy(ip_header)
        ip_header_copy[10] = ip_header_copy[11] = 0

        ip_calc_checksum = checksum(ip_header_copy)

        if ip_calc_checksum != ipv4_checksum:
            print(f'IPv4 header checksum {ipv4_checksum:04x} incorrect, should be: {ip_calc_checksum:04x}')

        # evaluate protocol (layer 6)
        protocol = ip_header[9]

        if protocol == 17:  # UDP
            udp_data = payload[ihl * 4:]

            ## verify checksum
            udp_checksum = get_uint16(udp_data[6:8])

            udp_length = get_uint16(udp_data[4:6])

            # create IPv4 pseudo header
            udp_header_copy = copy.deepcopy(udp_data[0:8])
            udp_header_copy[6] = udp_header_copy[7] = 0x00

            pseudo_header = ip_header[12:16] + ip_header[16:20] + bytearray([ 0x00, protocol ]) + bytearray([ udp_length >> 8, udp_length & 255]) + udp_header_copy + udp_data[8:]

            if len(pseudo_header) & 1:
                print(f'Pseudo header is odd in size {len(pseudo_header)}')

            assert len(pseudo_header) == 12 + len(udp_data)

            udp_calc_checksum = checksum(pseudo_header)

            if udp_calc_checksum != udp_checksum:
                print(f'{ipv4_addr_to_str(ip_header[12:16])} -> {ipv4_addr_to_str(ip_header[16:20])}')
                print(f'UDP header checksum {udp_checksum:04x} incorrect, should be: {udp_calc_checksum:04x}')
