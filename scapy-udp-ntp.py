#! /usr/bin/python3

from scapy.all import *

test = Ether()/IP(dst='192.168.3.2')/fuzz(UDP()/NTP())

while True:
    sendp(test, iface="myip")
