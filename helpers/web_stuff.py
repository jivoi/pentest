#!/usr/bin/python

import sys
import os
import re

if len(sys.argv) == 1:
    print "\nusage: \n "
    print "%s <URL> <type>" % sys.argv[0]
    print "%s <URL> <type> <full>" % sys.argv[0]
    print "%s <URL> <type> <log>" % sys.argv[0]
    print "%s <URL> <type> <full> <log>" % sys.argv[0]
    print "%s <URL> <all> <-- very slow" % sys.argv[0]
    print "\nScans:"
    print "nikto"
    print "dirb"
    print "wpscan"
    print "uniscan"

    sys.exit(0)

if str(sys.argv[1]) == 'fuzzdb':
    fuzzdb= "echo /opt/fuzzdb/ && ls --color=always /opt/fuzzdb/"
    os.system(fuzzdb)

    sys.exit(0)

URL=sys.argv[1]
IP=re.sub(r'[h|t|p|s|:|/]',r'',URL)

if str(sys.argv[2]) == 'uniscan':
    uniscan="uniscan -u %s -qweds" % (URL)
    os.system(uniscan)

if str(sys.argv[2]) == 'dirb':
    dirb="dirb %s" % (URL)
    os.system(dirb)

if str(sys.argv[2]) == 'nikto':
    nikto="nikto -host %s" % (URL)
    os.system(nikto)

if str(sys.argv[2]) == 'wpscan':
    wpscan="wpscan --batch --url %s" % (URL)
    os.system(wpscan)

if str(sys.argv[2]) == 'dirb' and str(sys.argv[3]) == 'full':
    dirbfull="dirb %s /usr/share/dirbuster/wordlists/directory-list-1.0.txt -w" % (URL)
    os.system(dirbfull)

if str(sys.argv[2]) == 'nikto' and str(sys.argv[3]) == 'full':
    niktofull="nikto -host %s -C all" % (URL)
    os.system(niktofull)

if str(sys.argv[2]) == 'wpscan' and str(sys.argv[3]) == 'full':
    wpscanfull="wpscan --batch --url %s --enumerate at,tt,t,ap,u[1-100]" % (URL)
    os.system(wpscanfull)

if str(sys.argv[2]) == 'dirb' and str(sys.argv[3]) == 'log':
    dirblog="dirb %s -o %s" % (URL, IP)
    os.system(dirblog)

if str(sys.argv[2]) == 'nikto' and str(sys.argv[3]) == 'log':
    niktolog="nikto -host %s -output . -Format csv" % (URL)
    os.system(niktolog)

if str(sys.argv[2]) == 'dirb' and str(sys.argv[3]) == 'full' and str(sys.argv[4]) == 'log':
    dirb=fulllog"dirb %s /usr/share/dirbuster/wordlists/directory-list-1.0.txt -w -o %s" % (URL, IP)
    os.system(dirbfulllog)

if str(sys.argv[2]) == 'nikto' and str(sys.argv[3]) == 'full' and str(sys.argv[4]) == 'log':
    niktofulllog="nikto -host %s -C all -output . -Format csv" % (URL)
    os.system(niktofulllog)

if str(sys.argv[2]) == 'wpscan' and str(sys.argv[3]) == 'full' and str(sys.argv[4]) == 'log':
    wpscan="wpscan --batch --url %s --enumerate at,tt,t,ap,u[1-100] | tee -a wps-%s" % (URL, IP)
    os.system(wpscanfulllog)

if str(sys.argv[2]) == 'all':
    dirball="dirb %s /usr/share/dirbuster/wordlists/directory-list-1.0.txt -w -o %s" % (URL, IP)
    niktoall="nikto -host %s -C all -output . -Format csv" % (URL)
    uniscanall="uniscan -u %s -qweds" % (URL)
    wpscanall="wpscan --batch --url %s --enumerate at,tt,t,ap,u[1-100] | tee -a wps-%s" % (URL, IP)
    os.system(dirball)
    os.system(niktoall)
    os.system(uniscanall)
    os.system(wpscanall)
