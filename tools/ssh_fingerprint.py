# python ./ssh_fingerprint.py localhost 22
# HostKey Type: ssh-rsa, Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDcdJkOXBtBA0AQZcSqfVpAu4dG3Jtfl1QizC/YAtIsfns1BOXvE/QFr0HMqFzQQ926+5Kbrwpf/uawnRdzNxLJAWB6Ue9nWelQom4CxmJ61agOVRLjbQ22BN2OwN764CPk5QcFXvuAsZZuOUFtHQHVEim/v+nZriYR8WDkjc9DuBc1ub+8dqSarkoKxMZ8aplYpZ8vLOH1NvX8qTSmrgGSzmIloNGEk4FS1qSNUiSTbSne/H/2V9WM75ap+dlrRAcy7+KmqT/twfNOF0OaJuwg9T4/OIIBz+uOvgAq65TKycaCEp3774DaLSoxnZkh6YBeLD1w+OUeQz2vSM/e2DRF (Fingerprint: d2:8f:eb:27:7e:53:4c:6e:38:3e:51:0b:57:4e:e3:c5)

import socket
import paramiko
import hashlib
import base64
import sys

if len(sys.argv) != 3:
    print "Usage: %s <ip> <port>" % sys.argv[0]
    quit()

try:
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mySocket.connect((sys.argv[1], int(sys.argv[2])))
except socket.error:
    print "Error opening socket"
    quit()

try:
    myTransport = paramiko.Transport(mySocket)
    myTransport.start_client()
    sshKey = myTransport.get_remote_server_key()
except paramiko.SSHException:
    print "SSH error"
    quit()

myTransport.close()
mySocket.close()

printableType = sshKey.get_name()
printableKey = base64.encodestring(sshKey.__str__()).replace('\n', '')
sshFingerprint = hashlib.md5(sshKey.__str__()).hexdigest()
printableFingerprint = ':'.join(a+b for a,b in zip(sshFingerprint[::2], sshFingerprint[1::2]))
print "HostKey Type: %s, Key: %s (Fingerprint: %s)" %(printableType, printableKey, printableFingerprint)