#!/usr/bin/env python

import socket
import sys
import argparse

class Knock(object):
	def __init__(self, ip, ports):
		super(Knock, self).__init__()
		self.ip = ip
		self.ports = ports

	def tcp_knock(self):
		for port in self.ports:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(0)
				s.connect((self.ip, port))
			except: pass
			s.close()

	def udp_knock(self):
		for port in self.ports:
			try:
				print "[UDP] Knocking on {0}:{1}".format(self.ip, port)
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sock.sendto("Give me Access", (self.ip, port))
			except: pass


def main():
    parser = argparse.ArgumentParser(description='Port Knocking with Python',
        epilog='Example: ./knock.py 192.168.1.2 4986 5320 5443')

    parser.add_argument('-i', '--ip', dest='ip', required=True,
                    help='Host name, IP Address')
    parser.add_argument('-u', '--udp', dest='udp',
                    help='Host name, IP Address')
    parser.add_argument('-p', '--ports', nargs='+', type=int, dest='ports', required=True,
                    help='Ports')

    args  = parser.parse_args()
    knock = Knock(args.ip, args.ports)

    if args.udp:
    	knock.udp_knock()
    	print "[UDP] Finished knocking on {0}".format(args.ip)
    else:
    	knock.tcp_knock()
    	print "[TCP] Finished knocking on {0}".format(args.ip)



if __name__ == '__main__':
	main()
