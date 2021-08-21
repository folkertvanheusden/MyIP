what this is
------------
This is an implementation of an IP-stack.
It will listen on a tap-device for ethernet frames containg e.g. ARP-
requests, IP packets, ICMP, UDP and even NTP and HTTP requests.


required
--------
C++ compiler
A posix system that has support for 'tap' virtual network devices (e.g.
Linux and BSD, see https://en.wikipedia.org/wiki/TUN/TAP ).


how to build
------------
	mkdir build
	cd build
	cmake ..
	make


how to run
----------
As root:

	./myip

Note: make sure you change the IP-address and such in main.cpp to reflect
the network configuration you like to have.

After you have started `myip', a 'myip' network device has appeared.

Run:

	./myiptop

...to see network statistics.

Run ./myiptop -j to see them as JSON.


notes
-----
The TCP functionality has some issues. That especiallt is clear in the
VNC server implementation, the http-server works fine (as long as the
response fits in 1 segment and is ACKed immediately).


badges
------
* <a href="https://scan.coverity.com/projects/folkertvanheusden-myip"><img alt="Coverity Scan Build status" src="https://scan.coverity.com/projects/23472/badge.svg"/></a>

* <img src="https://img.shields.io/github/license/folkertvanheusden/MyIP">

* <img src="https://img.shields.io/travis/com/folkertvanheusden/MyIP">


demo
----
See http://myip.vanheusden.com/

It also runs an NTP server.


(C) 2021 by Folkert van Heusden <mail@vanheusden.com>
Released under Apache License v2.0
