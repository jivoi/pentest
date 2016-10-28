#!/usr/bin/env python
import subprocess
import os
import sys
import reconf
from reconf import *

if len(sys.argv) != 2:
    print "Usage: enum_smb.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]

def cat(fname):
	fn = open(fname, 'r')
	fc = fn.read()
	print fc
	fn.close()

NMAPS = "nmap -n -sV -sU -sS -Pn -pT:139,445,U:137 --script=nbstat,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln-conficker,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061 -oA %s/%s_smb %s" % (reconf.exampth, ip_address, ip_address)
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
