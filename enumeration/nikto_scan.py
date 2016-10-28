#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 3:
    print "Usage: nikto_scan.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1]
port = sys.argv[2]

NIKTO = "nikto -host %s -p %s -C all | tee %s/%s_nikto_%s" % (ip_address, port, reconf.exampth, ip_address, port)
print "[+] Executing - %s" % (NIKTO)
results = subprocess.check_output(NIKTO, shell=True)