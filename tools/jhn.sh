#!/bin/sh
# john --rules --wordlist=/usr/share/wordlists/rockyou.txt --format=<format from hashid> <hash file>
# unshadow /etc/passwd /etc/shadow > unshadowed

# https://github.com/psypanda/hashID
# hashid.py -j <hash>
# hashid -j '$6$qcHTW61a$xQ8bRe16.XmOZ.eArVAIoUVsKmQBrQ1vFHIfeZomq39/AT61L2Sh89SIP4Mmew/ba7Lsa2laey4UD9wNd1'
# [+] SHA-512 Crypt [JtR Format: sha512crypt]

cd /root/offsecfw/tmp
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash.txt