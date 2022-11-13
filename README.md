what this is
------------
This is an implementation of an IP-stack (IPv4/IPv6).
It will listen on a tap-device for ethernet frames containg e.g. ARP-
requests, IP packets, ICMP(6), UDP and even NTP, VNC, SIP, MQTT and HTTP
requests. Also LLDP, NDP, socks, syslog, PPP, SLIP and SNMP.

required
--------
C++ compiler
A posix system that has support for 'tap' virtual network devices (e.g.
Linux and BSD, see https://en.wikipedia.org/wiki/TUN/TAP ).

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

Look at 'example.cfg' on how to configure the stack.

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

Use myip6.vanheusden.com for IPv6 access.

It also runs an NTP, SIP, SNMP, MQTT and VNC server.

copyright
---------
(C) 2021-2022 by Folkert van Heusden <mail@vanheusden.com>

Released under Apache License v2.0


my_ip.wav is spoken by https://www.fiverr.com/stephbritishvo
