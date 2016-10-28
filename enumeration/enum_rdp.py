#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_rdp.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -Pn -sV -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020.nse -oA %s/%s_rdp %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results
