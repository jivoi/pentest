#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 3:
    print "Usage: enum_http.py <ip address> <ports>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
ports = sys.argv[2].strip()

NMAPS = "nmap -n -sV -Pn -p %s --script=http-enum,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oA %s/%s_http %s" % (ports, reconf.exampth, ip_address, ip_address)

print "[+] Executing - %s" % (NMAPS)
results = subprocess.check_output(NMAPS, shell=True)
if results != "":
    print results

# E4L = "enum4linux -a %s" % (ip_address)
# results = subprocess.check_output(E4L, shell=True)
# if results != "":
# 	ofile = "%s/%s_enum4linux.txt" % (reconf.exampth,ip_address)
#         try:
#         	with open(ofile, 'a') as file:
#                         file.write(results)
#         except:
#         	print "ERROR: Couldn't write to %s" % (ofile)

# 	if os.path.isfile(ofile):
# 		cat(ofile)
# 	else:
# 		print "%s doesn't exists" % (ofile)
