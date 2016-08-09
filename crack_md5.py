#!/usr/bin/python
# Simple python code for crack md5 double salt
# md5($salt + $password + $salt)
# This encryption that I get with the hash format $md5 + $salt, and i found the static salt example like "Idontwanttosharethissalt"
# ./crack_md5.py hash.txt /usr/share/wordlists/rockyou.txt

import hashlib, os, sys
import time

try:
    dict = sys.argv[2]
    file = sys.argv[1]

except:
    print "[+] Usage: " + os.path.basename(__file__) + " hashfile wordlistfile"
    print "[+] Example: " + os.path.basename(__file__) + " hash.txt rockyou.txt"
    sys.exit(1)

staticsalt = "Idontwanttosharethissalt"
start = time.time()
end  = time.time()
class nonlocal:
    recover = 0

#parsing hash dan salt
def main():
    with open(file) as hashfile:
        print "[+] Cracking start"
        global hashsum
        hashsum = sum(1 for _ in hashfile)
        print "[+] Total Hash : %s\n" % (hashsum)
        hashfile.close()
    with open(file) as hashfile:
        salt = []
        hash = []
        for i in hashfile:
            pars = i.strip()
            hash = pars[0:32]
            salt = pars[33:]
            global salting
            salting = salt
            global crackdah
            crackdah = hash
            crack()

    hashfile.close()
    print "\n[+] Recovered  : %s/%s" % (nonlocal.recover, hashsum)
    print ("[+] Total Time : %s seconds " % format(time.time() - start))

#open wordlist
def crack():
    with open(dict) as dictfile:
        for n in dictfile:
            pwd = n.strip()
            global password
            password = pwd
            if hashlib.md5(staticsalt+password+salting).hexdigest() == crackdah:
                print "%s : %s" % (crackdah, password)
                nonlocal.recover += 1
                return main
    dictfile.close()
try:
    main()



except (KeyboardInterrupt, SystemExit):
    print "\n[+] Recovered      : %s/%s" % (nonlocal.recover, hashsum)
    print "[+] Not Recovered  : %s" % (hashsum - nonlocal.recover)
    print ("[+] Total Time     : %s seconds " % format(time.time() - start))
    print "\n[-] Exit"
