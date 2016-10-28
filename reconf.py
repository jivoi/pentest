#!/usr/bin/env python

import ConfigParser

def set_vars():
    global iprange
    global fulliprng
    global rootpth
    global labpath
    global rsltpth
    global exampth
    global nmappth
    global httpnse
    global wordlst
    global moderlst
    global shortlst
    global vulns
    global usrlst
    global pwdlst
    global fzzlst
    global opth
    global olst
    global nsepth
    global uagnt1
    global uagnt2
    global uagnt3
    global uagnt4
    global uagnt5
    global iframe1 

    config = ConfigParser.ConfigParser()
    config.read('recon.conf')

    iprange = config.get('hosts','iprange')
    fulliprng = config.get('hosts','fulliprng')
    opth = config.get('hosts','opth')
    olst = config.get('hosts','olst')

    rootpth = config.get('base','rootpth')
    labpath = config.get('base','labpath')

    basepth = config.get('paths','basepth')
    rsltpth = config.get('paths','rsltpth')
    exampth = config.get('paths','exampth')
    nmappth = config.get('paths','nmappth')
    wordlst = config.get('wordlist','wordlst')
    shortlst = config.get('wordlist','shortlst')
    moderlst = config.get('wordlist','moderlst')
    vulns = config.get('vuln','vulns')

    httpnse = config.get('nmapscripts','httpnse')
    nsepth = config.get('nmapscripts','nsepth')

    usrlst = config.get('crack','usrlst')
    pwdlst = config.get('crack','pwdlst')
    fzzlst = config.get('crack','fzzlst')
    
    uagnt1 = config.get('useragent','uagnt1')
    uagnt2 = config.get('useragent','uagnt2')
    uagnt3 = config.get('useragent','uagnt3')
    uagnt4 = config.get('useragent','uagnt4')
    uagnt5 = config.get('useragent','uagnt5')

    iframe1 = config.get('nastycode','iframe1')

set_vars()
