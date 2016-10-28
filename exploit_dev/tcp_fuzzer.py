#!/usr/bin/python
# Simple tcp fuzz against a target
import socket
from sys import exit,argv

if len(argv) < 2:
	print  "Performs a simple fuzz against a target"
	print "Usage: %s <Target IP Address/hostname> <Target Port>" % str(argv[0])
	exit(1)

#Create an arry of buffers, from 10 to 2000, with increments of 20.
buffer=["A"]
counter=100
while len(buffer) <= 30:
	buffer.append("A"*counter)
	counter=counter+200

for string in buffer:
	print "Fuzzing %s:%s with %s bytes" % (str(argv[1]),int(argv[2]),len(string))
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect((str(argv[1]),int(argv[2])))
	# This next part depends on whatever the RFC is for what you're trying to
	# exploit. Up to you to put the 'string' in the right place. Be sure to
	# receive bytes after sending anything.
	s.recv(1024) # Grab the banner, do not remove
	s.send(string + "\r\n") # Sends your evil buffer as 'string'
	s.send('QUIT\r\n') # Replace 'QUIT' with whatever ends your session
	s.close()
