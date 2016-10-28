#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_mysql.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

# NMAPS = "nmap -n -sV -Pn -p %s --script=mysql-audit,mysql-brute,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oA %s/%s_mysql %s" % (reconf.exampth, ip_address, ip_address)
NMAPS = "nmap -n -sV -sT -Pn -p 3306 --script=mysql-empty-password,mysql-vuln-cve2012-2122 -oA %s/%s_mysql %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results