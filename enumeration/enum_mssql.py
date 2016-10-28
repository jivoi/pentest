#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_mssql.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

NMAPS = "nmap -n -sV -sT -Pn -p 1433 --script=ms-sql-brute,ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-info,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell -oA %s/%s_mssql %s" % (reconf.exampth, ip_address, ip_address)
print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results