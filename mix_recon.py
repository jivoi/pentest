#!/usr/bin/env python

################################################################
## [Name]: mix_recon.py -- a recon/enumeration script
##--------------------------------------------------------------
## [Details]:
## This script is intended to be executed remotely against a
## list of IPs to perform a detailed nmap scan.
##
## As opposed to Mike's script, this one only recommends further
## actions together with the correct command line syntax for
## cut and past actions so you get immediate high level
## information and can focus your next steps a little better.
################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import sys
import time
import reconf
from reconf import *

print "\n"
print "############################################################"
print "####               NETWORK RECONNAISSANCE               ####"
print "############################################################"
print "\n"

if len(sys.argv) != 2:
    print "Usage: mix_recon.py <targets.txt>"
    print "Usage: mix_recon.py ./results/targets.txt"
    sys.exit(0)

# targets = sys.argv[1]
targets = open(sys.argv[1], 'r')

for ip_address in targets:
    ip_address = ip_address.strip()
    tcp_nmap_file = reconf.exampth + "/" + ip_address + "/" + ip_address + ".nmap"
    udp_nmap_file = reconf.exampth + "/" + ip_address + "/" + ip_address + "U.nmap"
    outputfile = reconf.exampth + "/" + ip_address + "/" + ip_address + ".mix_recon"
    tcpresults = open(tcp_nmap_file, 'r')
    serv_dict = {}
    for line in tcpresults:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            service = line.split(" ")[2]
            # print(service)
            port = line.split('/')[0]
            # print(port)
            if service in serv_dict:
                ports = serv_dict[service]
            ports.append(port)
            serv_dict[service] = ports
    # print(serv_dict)

    f = open(outputfile, 'w').close()
    f = open(outputfile, 'w')
    outputdir = reconf.exampth + "/" + ip_address

    for serv in serv_dict:
        ports = serv_dict[serv]
        if ("ftp" in serv) or ("tftp" in serv):
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found FTP service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts for further enumeration or hydra for password attack, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '%s/%s_ftp.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/seclists/Passwords/10k_most_common.txt -f -o %s/%s_ftphydra -u %s -s %s ftp\n" % (outputdir, ip_address, ip_address, port))
        elif (serv == "http"):
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found HTTP service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts, nikto or gobuster for further HTTP enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=http-enum,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN '%s/%s_http.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] nikto -h %s -p %s | tee %s/%s_nikto\n" % (ip_address, port, outputdir, ip_address))
                f.write("   [=] whatweb --no-errors http://%s | tee %s/%s_whatweb\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] wpscan -u http://%s | tee %s/%s_wpscan\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] wpscan -u http://%s --wordlist /usr/share/seclists/Passwords/10k_most_common.txt --username admin | tee %s/%s_wpscan_brute\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] gobuster -u http://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt | tee %s/%s_gobuster_top1000 \n" % (ip_address, port, outputdir, ip_address))
                f.write("   [=] gobuster -u http://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/common.txt | tee %s/%s_gobuster_common \n" % (ip_address, port, outputdir, ip_address))
        elif (serv == "ssl/http") or ("https" in serv):
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found HTTPS service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts, nikto or gobuster for further HTTPS enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=ssl-heartbleed,http-enum,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN '%s/%s_https.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] nikto -h %s -p %s > %s/%s_nikto_https.txt\n" % (ip_address, port, outputdir, ip_address))
                f.write("   [=] whatweb --no-errors https://%s | tee %s/%s_whatweb_https\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] wpscan -u https://%s | tee %s/%s_wpscan_https\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] wpscan -u https://%s --wordlist /usr/share/seclists/Passwords/10k_most_common.txt --username admin | tee %s/%s_wpscan_https_brute\n" % (ip_address, outputdir, ip_address))
                f.write("   [=] gobuster -u https://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt | tee %s/%s_gobuster_https_top1000 \n" % (ip_address, port, outputdir, ip_address))
                f.write("   [=] gobuster -u https://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/common.txt | tee %s/%s_gobuster_https_common \n" % (ip_address, port, outputdir, ip_address))
        elif "mysql" in serv:
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found MYSQL service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Check out the server for web applications with sqli vulnerabilities\n")
                f.write("   [>] Use nmap scripts for further MYSQL enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p %s --script=mysql-audit,mysql-brute,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN '%s/%s_mysql.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
        elif "ms-sql" in serv:
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found MSSQL service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts for further MSSQL enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=%s,smsql.username-sa,mssql.password-sa -oN %s/%s_mssql.nmap %s" % (port, port, outputdir, ip_address, ip_address))
                f.write("   [=] nmap -n -Pn -p%s --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=password,mssql.instance-port=%s,ms-sql-xp-cmdshell.cmd='ipconfig' -oN %s/%s_mssql_cmdshell.nmap %s" % (port, port, outputdir, ip_address, ip_address))
        elif ("microsoft-ds" in serv) or ("netbios-ssn" in serv):
            # print(ports)
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found SMB service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts or enum4linux for further enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -pT:139,%s,U:137 --script=nbstat,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln-conficker,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061 -oN '%s/%s_smb.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] enum4linux %s | tee %s/%s_enum4linux \n" % (ip_address, outputdir, ip_address))
                f.write("   [=] smbclient -L\\ -N -I %s | tee %s/%s_smbclient \n" % (ip_address, outputdir, ip_address))
        elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found RDP service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use ncrackpassword cracking, e.g\n")
                f.write("   [=] ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://%s\n" % (ip_address))
        elif "smtp" in serv:
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found SMTP service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts or smtp-user-enum for further SMTP enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=smtp* -oN '%s/%s_smtp.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t %s -p %s | tee %s/%s_smtp_enum \n" % (ip_address, port, outputdir, ip_address))
        elif "snmp" in serv or ("smux" in serv):
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found SNMP service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use nmap scripts, onesixtyone or snmwalk for further enumeration, e.g\n")
                f.write("   [=] nmap -n -sV -Pn -p%s --script=snmp-netstat,snmp-processes -oN '%s/%s_snmp.nmap' %s\n" % (port, outputdir, ip_address, ip_address))
                f.write("   [=] onesixtyone -c public %s | tee %s/%s_161\n" % (ip_address, ip_address, ip_address))
                f.write("   [=] snmpwalk -c public -v1 %s | tee %s/%s_snmpwalk \n" % (ip_address, outputdir, ip_address))
                f.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.4.1.77.1.2.25 | tee %s/%s_snmp_users \n" % (ip_address, outputdir, ip_address))
                f.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.6.13.1.3 | tee %s/%s_snmp_ports \n" % (ip_address, outputdir, ip_address))
                f.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.2 | tee %s/%s_snmp_process \n" % (ip_address, outputdir, ip_address))
                f.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.6.3.1.2 | tee %s/%s_snmp_software \n" % (ip_address, outputdir, ip_address))
        elif "ssh" in serv:
            for port in ports:
                # port = port.split("/")[0]
                f.write("[*] Found SSH service on %s:%s\n" % (ip_address, port))
                f.write("   [>] Use medusa or hydra (unreliable) for password cracking, e.g\n")
                f.write("   [=] medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h %s - %s -M ssh -f\n" % (ip_address, port))
                f.write("   [=] medusa -U /usr/share/seclists/Usernames/top_shortlist.txt -P /usr/share/seclists/Passwords/best110.txt -e ns -h %s - %s -M ssh -f\n" % (ip_address, port))
                f.write("   [=] hydra -f -V -t 1 -l root -P /usr/share/wordlists/rockyou.txt -s %s %s ssh\n" % (port, ip_address))
    f.close()
    print "[*] Mix recon scan completed for %s. Check %s" % (ip_address, outputfile)