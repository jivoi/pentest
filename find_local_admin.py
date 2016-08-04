#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

-------------------------------------------------------------------------------

Invoke nmap scan and parse results to find local admin rights
nmap -p 445 --open --script=smb-enum-shares.nse --script-args smbuser=<USERNAME>
,smbpass=<USERPASS>,smbdomain=<DOMAIN>

NOTE - ENCLOSE PASSWORD IN QUOTES IF CONTAINS SPECIAL CHARACTERS LIKE $

Based on parseadmin.rb script by zeknox
http://www.pentestgeek.com/2012/08/23/creds-or-hash-where-the-admin-at/

-------------------------------------------------------------------------------

TODO - check out nmap issues not always reporting successful logon to 
machines with known good creds?!? Nmap results are not perfect!

'''

import sys
import argparse
import subprocess
import os
import string
from xml.dom import minidom

def parse_nmap(nmap_outfilename):
    
    dom = minidom.parse(nmap_outfilename)
    
    hosts = dom.getElementsByTagName("host")
    for host in hosts:
        
        address = host.getElementsByTagName("address")[0].getAttribute("addr")
        hostnames = host.getElementsByTagName("hostnames")
        for hostname in hostnames:
            try:
                name = hostname.getElementsByTagName("hostname")[0].getAttribute("name")
            except:
                pass

        try:
            script_results = host.getElementsByTagName("hostscript")[0].getElementsByTagName("script")[0].getAttribute("output")
        except:
            script_results = ""
        
        if string.find(script_results,"WRITE") != -1:        
            output_str = "[+] local admin on " + address
            try:
                if name[0] != "":
                    output_str += "  (" + name + ")"
            except:
                pass
            
            print output_str

def main(argv):
    
    parser = argparse.ArgumentParser(description='Invoke nmap scan and parse results to find local admin rights')
    parser.add_argument("--target", "-t", required=True, action="store", help="Host target specification in nmap format")
    parser.add_argument("--username", "-u", required=True, action="store", help="Windows / AD username")
    parser.add_argument("--password", "-p", required=True, action="store", help='Windows / AD password')
    parser.add_argument("--domain", "-d", default="", action="store", help='AD domain')
    args = parser.parse_args()
    
    target = args.target
    username = args.username
    password = args.password
    domain = args.domain
    output_filename = "nmap_local_admin.tmp"
    
    nmap_command = "nmap -p 445 --open --script=smb-enum-shares.nse --script-args "
    nmap_command += "smbuser="+ username
    nmap_command += ",smbpass=" + password
    if domain != "":
        nmap_command += ",smbdomain=" + domain
    nmap_command += " -oX " + output_filename
    nmap_command += " " + target
    
    print "Running command:\n" + nmap_command
    
    subprocess.Popen(nmap_command, shell=True).wait()
        
    parse_nmap(output_filename)
    
    try:
        # Delete old temp files if the user wants to; default to leave old files
        response = raw_input("\nDelete temporary nmap output file? [yes]")
        if "n" in response or "N" in response:
            pass
        else:
            print("Deleting temp file...\n")
            os.remove(output_filename)
    except:
        pass
    
if __name__ == "__main__":
    main(sys.argv[1:])