#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_oracle.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -n -sV -sT -Pn -p 1521 --script=oracle-brute.nse,oracle-brute-stealth.nse,oracle-enum-users.nse,oracle-sid-brute -oA %s/%s_oracle %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results