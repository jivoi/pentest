#!/usr/bin/python
 
import socket
import sys

if len(sys.argv) != 4:
	 print "Usage:smtp_vrfy <serverIP> <userlist.txt> ,outputfile.txt>"
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
out.write('Active email accounts on server ' + server + ': \r')

# VRFY users in input file
f=open(userfile)
line=f.readline()
print "Beginning check... \n"
while line:
	line=line.strip()
	print 'Checking for user ' + line
	s.send('VRFY ' + line + '\r\n')
	result=s.recv(1024)
	print result
	
	if result.startswith('250'):
		out.write(result + '\r')
	result=""
	line=f.readline()

# Cleanup
s.close()
f.close()
out.close()
 
