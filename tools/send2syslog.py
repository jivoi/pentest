#!/usr/bin/python

# usage: $0 <target ip> <message>

from scapy.all import *
import sys
import time

target = sys.argv[1]
msg = sys.argv[2]

for prio in range(0, 7):
	for faci in range(0, 23):
		priority = (prio << 3) | faci
		syslog = IP(dst=target)/UDP(dport=514)/Raw(load='<' + str(priority) + '>' + time.strftime("%b %d %H:%M:%S ") + msg)
		send(syslog, verbose=0)
		sys.stdout.write(".")
		sys.stdout.flush()

print ""
