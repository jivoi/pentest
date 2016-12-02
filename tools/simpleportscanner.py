#!/usr/bin/env python
import socket
from multiprocessing.dummy import Pool as ThreadPool
import sys
from datetime import datetime

# Clear the screen
# subprocess.call('cls', shell=True)

# Ask for input
remoteServer    = raw_input("Enter a remote host to scan: ")
remoteServerIP  = socket.gethostbyname(remoteServer)

# Print a nice banner with information on which host we are about to scan
print "-" * 60
print "Please wait, scanning remote host", remoteServerIP
print "-" * 60

# Check what time the scan started
t1 = datetime.now()

# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

# We also put in some error handling for catching errors

def scan(ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((remoteServerIP, ports))
    if result == 0:
        byte = str.encode("Server:\r\n")
        sock.send(byte)
        banner = sock.recv(1024)
        print "Port {}: 	 Open".format(ports), " - ", banner
    sock.close()

# function to be mapped over
def scanParallel(ports, threads=4):
    pool = ThreadPool(threads)
    results = pool.map(scan, ports)
    pool.close()
    pool.join()
    return results

if __name__ == "__main__":
    ports =(20,21,22,23,53,69,80,88,110,123,135,137,138,139,143,161,389,443,445,464,512,513,631,860,1080,1433,1434,3124,3128,3306,3389,5800,5900,8080,10000)
    results = scanParallel(ports, 4)

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total =  t2 - t1

# Printing the information to screen
print 'Scanning Completed in: ', total
