#! /usr/bin/python3

from scapy.all import *

test = Ether()/fuzz(IP(dst='192.168.3.2'))/fuzz(TCP())

while True:
    sendp(test, iface="myip")
