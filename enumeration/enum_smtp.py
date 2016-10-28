#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_smtp.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -n -sV -sT -Pn -p 25,465,587 --script=smtp-commands,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 -oA %s/%s_smtp %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results