what this is
------------
This is an implementation of an IP-stack (IPv4/IPv6).
It will listen on a tap-device for ethernet frames containg e.g. ARP-
requests, IP packets, ICMP(6), UDP and even NTP, VNC, SIP, MQTT and HTTP
requests. Also LLDP, NDP, Socks, syslog, PPP, SLIP, NRPE, DNS (client),
SCTP, MDNS and SNMP.

required
--------
* C++ compiler
* A posix system that has support for 'tap' virtual network devices (e.g. Linux and BSD, see https://en.wikipedia.org/wiki/TUN/TAP ) or "promiscuous mode".

how to build
------------
Make sure you have "libssl-dev", "libncurses-dev", "libconfig++-dev", "libspeex-dev", "libsamplerate0-dev", "zlib1g-dev" and "libsndfile1-dev" installed. Then:

* mkdir build
* cd build
* cmake ..
* make

how to run
----------
As root:

	./myip configuration-file.cfg

Look at 'example.cfg' to see what is possible.

Ideally you have a computer/virtual machine with 2 network-interfaces (or a serial port for PPP/SLIP). Then one port would be the usual LAN port, the other can be assigned to MyIP. The MyIP port can be used as a TAP-device or via "promiscuous-mode".


After you have started `myip', a 'myip' network device has appeared.
Of course, your "local IP address" must be configured (remote is the MyIP instance, local is the Linux system; so for the example.ini: 192.168.3.2 is the MyIP address and you could e.g. add 192.168.3.1 to the 'myip' network interface).

Run:

	./myiptop

...to see network statistics.

Run ./myiptop -j to see them as JSON.

notes
-----
The TCP functionality has some issues.

demo
----
See http://myip.vanheusden.com/

It listens to both IPv4 as well as IPv6. It performs HTTP over TCP but also over SCTP.

It also runs an MQTT, NRPE, NTP, SIP, SNMP and VNC server.

copyright
---------
(C) 2021-2022 by Folkert van Heusden <mail@vanheusden.com>

Released under Apache License v2.0


my_ip.wav is spoken by https://www.fiverr.com/stephbritishvo
