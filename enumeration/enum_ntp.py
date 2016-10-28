#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_ntp.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -n -Pn -sU -p 123 --script=ntp-info -oA %s/%s_ntp %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results