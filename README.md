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
Make sure you have "libiniparser-dev" installed. Then:

* mkdir build
* cd build
* cmake ..
* make

how to run
----------
As root:

	./myip configuration-file.ini

Look at 'example.ini' on how to configure the stack.

After you have started `myip', a 'myip' network device has appeared.

Run:

	./myiptop

...to see network statistics.

Run ./myiptop -j to see them as JSON.

notes
-----
The TCP functionality has some issues.

badges
------
<a href="https://scan.coverity.com/projects/folkertvanheusden-myip"><img alt="Coverity Scan Build status" src="https://scan.coverity.com/projects/23472/badge.svg"/></a>
<img src="https://img.shields.io/github/license/folkertvanheusden/MyIP">
<img src="https://img.shields.io/travis/com/folkertvanheusden/MyIP">
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/9f791b96f10a48eba323215bc5feed1a)](https://www.codacy.com/gh/folkertvanheusden/MyIP/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=folkertvanheusden/MyIP&amp;utm_campaign=Badge_Grade)

demo
----
See http://myip.vanheusden.com/

It also runs an NTP server.

copyright
---------
(C) 2021 by Folkert van Heusden <mail@vanheusden.com>
Released under Apache License v2.0
