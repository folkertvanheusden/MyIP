#! /bin/sh

/usr/sbin/brctl addif br0 myip

/usr/sbin/ifconfig myip up
