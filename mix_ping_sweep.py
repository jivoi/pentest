#!/usr/bin/env python
##########################################################################
## [Name]: mix_ping_sweep.py -- a recon/enumeration script
##------------------------------------------------------------------------
## [Details]:
## Script to perform a ping sweep over a given range and list each live
## host in file <outputdir>/targets.txt.
##------------------------------------------------------------------------
## [Usage]:
## python mix_ping_sweep.py <target IP range> <output directory>
##########################################################################

import subprocess
import sys
import os

if len(sys.argv) != 3:
    print "\nUsage: mix_ping_sweep.py <range> <output directory>\n"
    print "\nUsage: mix_ping_sweep.py 192.168.56.1-254 ./results\n"
    sys.exit(0)

RANGE = sys.argv[1].strip()
OUTDIR = sys.argv[2].strip()


try:
    os.stat(OUTDIR)
except:
    os.mkdir(OUTDIR)
    print " "
    print "[!] %s didn't exist, created %s" % (OUTDIR, OUTDIR)

outfile = OUTDIR + "/targets.txt"

res = 0
f = open(outfile, 'aw')
print " "
print "[+] Performing ping sweep over %s" % (RANGE)
SWEEP = "nmap -n -sn %s" % (RANGE)
#SWEEP = "nmap -n -sn -PS %s" % (RANGE) # TCP_SYN ping scan
#SWEEP = "nmap -n -sn -PA %s" % (RANGE) # TCP_ACK ping scan
results = subprocess.check_output(SWEEP, shell=True)
lines = results.split("\n")
for line in lines:
    line = line.strip()
    line = line.rstrip()
    if ("Nmap scan report for" in line):
        ip_address = line.split(" ")[4]
        try:
            os.stat(OUTDIR + "/" + ip_address)
        except:
            os.mkdir(OUTDIR + "/" + ip_address)
            print " "
            print "[!] %s didn't exist in %s, creating..." % (ip_address, OUTDIR)
        if (res > 0):
            f.write('\n')
        f.write("%s" % (ip_address))
        print "[*] %s" % (ip_address)
        res += 1
print " "
print "[*] Found %s live hosts" % (res)
print "[*] Created target list %s" % (outfile)
print "[*] Run mix_port_scan.sh -t %s -p all" % (outfile)
print " "
f.close()
