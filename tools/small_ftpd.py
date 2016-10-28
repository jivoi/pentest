#!/usr/bin/env python

# Small and quick FTP daemon used to quickly transfer files via FTP
# requires pyftpdlib
# pip install pyftpdlib
# python small_ftpd.py -u user -p user -d /tmp/ -a

# imports
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from sys import argv
import argparse

# Required command line switches
parser = argparse.ArgumentParser(prog=str(argv[0]), usage='%(prog)s [options]', description='Small and quick FTP server daemon used to quickly transfer files via FTP')
parser.add_argument('-u', help='Username that can connect to the FTP server (full rights)', required=True, dest='user')
parser.add_argument('-p', help='Password for user that can connect to the FTP server', required=True, dest='password')
parser.add_argument('-d', help='Directory to be used for FTP root', required=True, dest='ftproot')

# Optional command line switches
parser.add_argument('-P', help='Port to run FTP instance on', default=21, dest='port')
parser.add_argument('-a', help='Allow anonymous (read-only) logins', action='store_true', default='store_false', dest='anon')
parser.add_argument('-H', help='IP/hostname to bind FTP instance to', default='0.0.0.0', dest='host')

# parse arguments
args = parser.parse_args()
argsdict = vars(args)
user = argsdict['user']
password = argsdict['password']
ftproot = argsdict['ftproot']
port = argsdict['port']
anon = argsdict['anon']
host = argsdict['host']


# Begin authorization
authorizer = DummyAuthorizer()
authorizer.add_user(user, password, ftproot, perm="elradfmw")
if anon == True:
	authorizer.add_anonymous(ftproot, perm="elm")

# Initalize the FTP Handler
handler = FTPHandler
handler.authorizer = authorizer
handler.banner = "Microsoft FTP Service" # because stealth

# Define the FTP Service
server = FTPServer((host, int(port)), handler)

# Run until ^C
server.serve_forever()
