#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 4:
	print "Enumerates email accounts by initiating an email and resetting before being sent \r\n"
	print "Usage:smtp_rst <serverIP> <userlist.txt> ,outputfile.txt>"
	sys.exit(0)

# Define input variables
server=sys.argv[1]
userfile=sys.argv[2]
outputfile=sys.argv[3]

#Create a socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
connect=s.connect((server,25))

# Recieve the banner
banner=s.recv(1024)
print banner

# Open output file for writing
out=open(outputfile, "a")
out.write('Output ' + server + ': \r')

# VRFY users in input file
f=open(userfile)
line=f.readline()
print "Beginning check... \n"
while line:
	line=line.strip()
	print 'Checking for user ' + line
	s.send('EHLO testuser')
	s.send('MAIL FROM: testuser@nomail.com \r\n')
	result=s.recv(1024)
	print result
	s.send('RCPT TO: ' + line + '\r\n')
	result=s.recv(1024)
	print result
		
	if result.startswith('250'):
		out.write(result + '\r')
		s.send ('RSET')
	result=""
	line=f.readline()

# Cleanup
s.send ('QUIT \r\n')
s.close()
f.close()
out.close()