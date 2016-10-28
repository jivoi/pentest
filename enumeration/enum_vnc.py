#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_vnc.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -n -sV -sT -Pn -p 5900 --script=realvnc-auth-bypass,vnc-brute,vnc-info --script-args=unsafe=1 -oA %s/%s_vnc %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results