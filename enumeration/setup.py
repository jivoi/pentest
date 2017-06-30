#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import *
import os
import sys
import time
import re
import hashlib
import pip
installed_packages = pip.get_installed_distributions()
import reconf
from reconf import *

def chkfolders():
    dpths = [reconf.rsltpth,reconf.exampth,reconf.nmappth]
    for dpth in dpths:
        if not os.path.exists(dpth):
            print "[!] %s folder is missing, creating it now..." % (dpth)
            os.makedirs(dpth)
    else:
        print "[+] We're okay, %s folder exists" % (dpth)

def createList(ipadr):
   nm = nmap.PortScanner()
   args = "-sP -PS -n -oG %s " % (reconf.opth)
   nm.scan(ipadr,arguments=args)
   fo = open(reconf.olst,"w")
   with open(reconf.opth) as input:
        for line in input:
                line = line.split(" ")
                if re.match('[a-zA-Z]',line[1]) is None:
                        fo.write("%s\n" % (line[1]))
   fo.close()

def upnsedb(url):
    NSE = "wget -c %s -P %s" % (url, reconf.nsepth)
    print "[!] Fetching %s " % (nsefile)
    subprocess.call(NSE, shell=True)
    print "[+] Updating Nmap database with %s " % (nsefile)
    UPNSEDB = "nmap --script-updatedb"
    subprocess.call(UPNSEDB, shell=True)

def install(package):
    pip.main(['install', package])

def hashfile(afile, hasher, blocksize=65536):
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.digest()

if __name__=='__main__':
    print "[*] Installing missing NSE scripts..."
    nsearray = ['http-screenshot-html.nse','smb-check-vulns.nse']
    for nsefile in nsearray:
        nsescript = "%s/%s" % (reconf.nsepth, nsefile)
        if not os.path.isfile(nsescript):
            if re.search('http-screenshot-html.nse', nsefile):
                upnsedb('https://raw.githubusercontent.com/afxdub/http-screenshot-html/master/http-screenshot-html.nse')
            if re.search('smb-check-vulns.nse', nsefile):
                upnsedb('https://svn.nmap.org/nmap-exp/scriptsuggest/scripts/smb-check-vulns.nse')
        else:
            print "[+] %s is already installed" % (nsefile)

    FN = "wkhtmltoimage"
    TAR = "wkhtmltox-0.12.3_linux-generic-i386.tar.xz"
    URL = "wget -c http://download.gna.org/wkhtmltopdf/0.12/0.12.3/%s" % (TAR)
    EXT = "wkhtmltox/bin/%s" % (FN)
    BIN = "/usr/local/bin/"
    BFN = "%s/%s" % (BIN, FN)
    TXZ = "tar -xJvf %s" % (TAR)
    CXZ = "cp %s %s" % (EXT, BIN)
    print "[*] Checking for the installation of %s..." % (FN)
    if not os.path.isfile(BFN):
        # if os.path.isfile(TAR):
        print "[+] Downloading wkhtmltoimage..."
        filename = subprocess.call(URL, shell=True)
        if os.path.isfile(TAR):
            print "[+] Extracting %s file %s to %s..." % (TAR, EXT, BIN)
            subprocess.call(TXZ, shell=True)
            subprocess.call(CXZ, shell=True)
            if not os.path.isfile(BFN):
                print "[!] %s not found in %s" % (FN, BIN)
            else:
                print "[+] %s is install to %s" % (FN, BIN)
    else:
        print "[+] We're good: %s is installed" % (FN)

    print "[*] Checking for the necessary folders..."
    chkfolders()

    print "[*] Checking if the required modules are installed..."
    pkgs = ['ftputil', 'pywinrm', 'xsser', 'python-libnmap', 'python-nmap', 'easyprocess']
    fipkgs = [package.project_name for package in installed_packages]
    for pkgname in pkgs:
        if pkgname in fipkgs:
            print "[+] The %s module is installed..." % (pkgname)
        else:
            print "[!] The %s module hasn't been installed yet..." % (pkgname)
            print "[!] Installing %s module now..." % (pkgname)
            install(pkgname)

    print "[*] Create list of active IPs"
    createList(reconf.iprange)

    # TAR = "nmap_nse_vulscan-2.0.tar.gz"
    # URL = "wget -c https://github.com/jivoi/pentest/raw/master/%s" % (TAR)
    # VPT = "%s/vulscan" % (reconf.nsepth)
    # TXZ = "tar -xzvf %s -C %s" % (TAR, reconf.nsepth)
    # CXZ = "cp %s/vulscan.nse %s" % (VPT, reconf.nsepth)
    # print "[*] Checking if vulnscan is installed..."
    # if not os.path.isdir(VPT):
    #     if not os.path.isfile(TAR):
    #         print "[+] Downloading %s.." % (TAR)
    #         subprocess.call(URL, shell=True)
    #         print "[+] Extracting %s to %s..." % (TAR, reconf.nsepth)
    #         subprocess.call(TXZ, shell=True)
    #         subprocess.call(CXZ, shell=True)
    #         UPNSEDB = "nmap --script-updatedb"
    #         subprocess.call(UPNSEDB, shell=True)
    # else:
    #     print "[+] We're good: vulscan is installed"
