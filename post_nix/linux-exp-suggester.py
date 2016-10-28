#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import shutil
import urllib
import platform
from optparse import OptionParser


h00lyshit = {
    'Name': 'h00lyshit',
    'Kernel': ['2.6.8', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16'],
    'CVE': '2006-3626',
    'Source': 'http://www.exploit-db.com/exploits/2013/',
}
elflbl = {
    'Name': 'elflbl',
    'Kernel': ['2.4.29'],
    'Source': 'http://www.exploit-db.com/exploits/744/',
}
krad3 = {
    'Name': 'krad3',
    'Kernel': ['2.6.5', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11'],
    'Source': 'http://exploit-db.com/exploits/1397/',
}
w00t = {
    'Name': 'w00t',
    'Kernel': ['2.4.10', '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21'],
    'Source': '',
}
brk = {
    'Name': 'brk',
    'Kernel': ['2.4.10', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22'],
    'Source': '',
}
elfdump = {
    'Name': 'elfdump',
    'Kernel': ['2.4.27'],
    'Source': '',
}
elfcd = {
    'Name': 'elfcd',
    'Kernel': ['2.6.12'],
    'Source': '',
}
expand_stack = {
    'Name': 'expand_stack',
    'Kernel': ['2.4.29'],
    'Source': '',
}
kdump = {
    'Name': 'kdump',
    'Kernel': ['2.6.13'],
    'Source': '',
}
km2 = {
    'Name': 'km2',
    'Kernel': ['2.4.18', '2.4.22'],
    'Source': '',
}
krad = {
    'Name': 'krad',
    'Kernel': ['2.6.5', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11'],
    'Source': '',
}
local26 = {
    'Name': 'local26',
    'Kernel': ['2.6.13'],
    'Source': '',
}
loko = {
    'Name': 'loko',
    'Kernel': ['2.4.22', '2.4.23', '2.4.24'],
    'Source': '',
}
mremap_pte = {
    'Name': 'mremap_pte',
    'Kernel': ['2.4.20', '2.2.24', '2.4.25', '2.4.26', '2.4.27'],
    'Source': 'http://www.exploit-db.com/exploits/160/',
}
newlocal = {
    'Name': 'newlocal',
    'Kernel': ['2.4.17', '2.4.19'],
    'Source': '',
}
ong_bak = {
    'Name': 'ong_bak',
    'Kernel': ['2.6.5'],
    'Source': '',
}
ptrace = {
    'Name': 'ptrace',
    'Kernel': ['2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22'],
    'Source': '',
}
ptrace_kmod = {
    'Name': 'ptrace_kmod',
    'Kernel': ['2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22'],
    'CVE': '2007-4573',
    'Source': '',
}
ptrace_kmod2 = {
    'Name': 'ptrace_kmod2',
    'Kernel': ['2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34'],
    'CVE': '2010-3301',
    'Source': 'http://www.exploit-db.com/exploits/15023/',
}
ptrace24 = {
    'Name': 'ptrace24',
    'Kernel': ['2.4.9'],
    'Source': '',
}
pwned = {
    'Name': 'pwned',
    'Kernel': ['2.6.11'],
    'Source': '',
}
py2 = {
    'Name': 'py2',
    'Kernel': ['2.6.9', '2.6.17', '2.6.15', '2.6.13'],
    'Source': '',
}
raptor_prctl = {
    'Name': 'raptor_prctl',
    'Kernel': ['2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17'],
    'CVE': '2006-2451',
    'Source': 'http://www.exploit-db.com/exploits/2031/',
}
prctl = {
    'Name': 'prctl',
    'Kernel': ['2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17'],
    'Source': 'http://www.exploit-db.com/exploits/2004/',
}
prctl2 = {
    'Name': 'prctl2',
    'Kernel': ['2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17'],
    'Source': 'http://www.exploit-db.com/exploits/2005/',
}
prctl3 = {
    'Name': 'prctl3',
    'Kernel': ['2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17'],
    'Source': 'http://www.exploit-db.com/exploits/2006/',
}
prctl4 = {
    'Name': 'prctl4',
    'Kernel': ['2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17'],
    'Source': 'http://www.exploit-db.com/exploits/2011/',
}
remap = {
    'Name': 'remap',
    'Kernel': ['2.4.'],
    'Source': '',
}
rip = {
    'Name': 'rip',
    'Kernel': ['2.2.'],
    'Source': '',
}
stackgrow2 = {
    'Name': 'stackgrow2',
    'Kernel': ['2.4.29', '2.6.10'],
    'Source': '',
}
uselib24 = {
    'Name': 'uselib24',
    'Kernel': ['2.6.10', '2.4.17', '2.4.22', '2.4.25', '2.4.27', '2.4.29'],
    'Source': '',
}
newsmp = {
    'Name': 'newsmp',
    'Kernel': ['2.6.'],
    'Source': '',
}
smpracer = {
    'Name': 'smpracer',
    'Kernel': ['2.4.29'],
    'Source': '',
}
loginx = {
    'Name': 'loginx',
    'Kernel': ['2.4.22'],
    'Source': '',
}
expsh = {
    'Name': 'exp.sh',
    'Kernel': ['2.6.9', '2.6.10', '2.6.16', '2.6.13'],
    'Source': '',
}
vmsplice1 = {
    'Name': 'vmsplice1',
    'Kernel': ['2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.24.1'],
    'CVE': '2008-0600',
    'Source': 'http://www.exploit-db.com/exploits/5092',
}
vmsplice2 = {
    'Name': 'vmsplice2',
    'Kernel': ['2.6.23', '2.6.24'],
    'CVE': '2008-0600',
    'Source': 'http://www.exploit-db.com/exploits/5093',
}
vconsole = {
    'Name': 'vconsole',
    'Kernel': ['2.6.'],
    'CVE': '2009-1046',
    'Source': '',
}
sctp = {
    'Name': 'sctp',
    'Kernel': ['2.6.26'],
    'CVE': '2008-4113',
    'Source': '',
}
ftrex = {
    'Name': 'ftrex',
    'Kernel': ['2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22'],
    'CVE': '2008-4210',
    'Source': 'http://www.exploit-db.com/exploits/6851',
}
exit_notify = {
    'Name': 'exit_notify',
    'Kernel': ['2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29'],
    'Source': 'http://www.exploit-db.com/exploits/8369',
}
udev = {
    'Name': 'udev',
    'Kernel': ['2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29'],
    'CVE': '2009-1185',
    'Source': 'http://www.exploit-db.com/exploits/8478',
}
sock_sendpage2 = {
    'Name': 'sock_sendpage2',
    'Kernel': ['2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15', '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27', '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33', '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30'],
    'CVE': '2009-2692',
    'Source': 'http://www.exploit-db.com/exploits/9436',
}
sock_sendpage = {
    'Name': 'sock_sendpage',
    'Kernel': ['2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15', '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27', '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33', '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30'],
    'CVE': '2009-2692',
    'Source': 'http://www.exploit-db.com/exploits/9435',
}
udp_sendmsg_32bit = {
    'Name': 'udp_sendmsg_32bit',
    'Kernel': ['2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19'],
    'CVE': '2009-2698',
    'Source': 'http://downloads.securityfocus.com/vulnerabilities/exploits/36108.c',

}
pipec_32bit = {
    'Name': 'pipe.c_32bit',
    'Kernel': ['2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15', '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27', '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33', '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31'],
    'CVE': '2009-3547',
    'Source': 'http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c',
}
do_pages_move = {
    'Name': 'do_pages_move',
    'Kernel': ['2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31'],
    'CVE': '2010-0415',
    'Source': '',
}
reiserfs = {
    'Name': 'reiserfs',
    'Kernel': ['2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34'],
    'CVE': '2010-1146',
    'Source': 'http://www.exploit-db.com/exploits/12130/',
}
can_bcm = {
    'Name': 'can_bcm',
    'Kernel': ['2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-2959',
    'Source': 'http://www.exploit-db.com/exploits/14814/',
}
rds = {
    'Name': 'rds',
    'Kernel': ['2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-3904',
    'Source': 'http://www.exploit-db.com/exploits/15285/',
}
half_nelson = {
    'Name': 'half_nelson',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-3848',
    'Source': 'http://www.exploit-db.com/exploits/6851',
}
half_nelson1 = {
    'Name': 'half_nelson1',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-3848',
    'Source': 'http://www.exploit-db.com/exploits/17787/',
}
half_nelson2 = {
    'Name': 'half_nelson2',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-3850',
    'Source': 'http://www.exploit-db.com/exploits/17787/',
}
half_nelson3 = {
    'Name': 'half_nelson3',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-4073',
    'Source': 'http://www.exploit-db.com/exploits/17787/',
}
caps_to_root = {
    'Name': 'caps_to_root',
    'Kernel': ['2.6.34', '2.6.35', '2.6.36'],
    'Source': 'http://www.exploit-db.com/exploits/15916/',
}
american_sign_language = {
    'Name': 'american_sign_language',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-4347',
    'Source': 'http://downloads.securityfocus.com/vulnerabilities/exploits/45408.c',
}
pktcdvd = {
    'Name': 'pktcdvd',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36'],
    'CVE': '2010-3437',
    'Source': 'http://www.exploit-db.com/exploits/15150/',
}
video4linux = {
    'Name': 'video4linux',
    'Kernel': ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33'],
    'CVE': '2010-3081',
    'Source': 'http://www.exploit-db.com/exploits/15024/',
}
memodipper = {
    'Name': 'memodipper',
    'Kernel': ['2.6.39', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.1.0'],
    'CVE': '2012-0056',
    'Source': 'http://www.exploit-db.com/exploits/18411/',
}
semtex = {
    'Name': 'semtex',
    'Kernel': ['2.6.37', '2.6.38', '2.6.39', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.1.0'],
    'CVE': '2013-2094',
    'Source': 'http://www.exploit-db.com/download/25444/',
}
perf_swevent = {
    'Name': 'perf_swevent',
    'Kernel': ['3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.1.0', '3.2', '3.3', '3.4.0', '3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6', '3.4.8', '3.4.9', '3.5', '3.6', '3.7', '3.8.0', '3.8.1', '3.8.2', '3.8.3', '3.8.4', '3.8.5', '3.8.6', '3.8.7', '3.8.8', '3.8.9'],
    'CVE': '2013-2094',
    'Source': 'http://www.exploit-db.com/download/26131',
}
msr = {
    'Name': 'msr',
    'Kernel': ['2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36', '2.6.37', '2.6.38', '2.6.39', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.1.0', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7.0', '3.7.6'],
    'CVE': '2013-0268',
    'Source': 'http://www.exploit-db.com/exploits/27297/',
}
timeoutpwn = {
    'Name': 'timeoutpwn',
    'Kernel': ['3.4', '3.5', '3.6', '3.7', '3.8', '3.8.9', '3.9', '3.10', '3.11', '3.12', '3.13', '3.4.0', '3.5.0', '3.6.0', '3.7.0', '3.8.0', '3.8.5', '3.8.6', '3.8.9', '3.9.0', '3.9.6', '3.10.0', '3.10.6', '3.11.0', '3.12.0', '3.13.0', '3.13.1'],
    'CVE': '2014-0038',
    'Source': 'http://www.exploit-db.com/exploits/31346/',
}
rawmodePTY = {
    'Name': 'rawmodePTY',
    'Kernel': ['2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36', '2.6.37', '2.6.38', '2.6.39', '3.14', '3.15'],
    'CVE': '2014-0196',
    'Source': 'http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c',
}


exploits = [
    h00lyshit, elflbl, krad, krad3, w00t, elfdump, brk, elfcd, expand_stack,
    kdump, km2, local26, loko, mremap_pte, newlocal, ong_bak, ptrace, ptrace_kmod,
    ptrace_kmod2, ptrace24, pwned, py2, raptor_prctl, prctl, prctl2, prctl3, prctl4,
    remap, rip, stackgrow2, uselib24, newsmp, smpracer, loginx, expsh, vmsplice1,
    vmsplice2, vconsole, sctp, ftrex, exit_notify, udev, sock_sendpage2, sock_sendpage, pipec_32bit,
    do_pages_move, reiserfs, can_bcm, rds, half_nelson, half_nelson1, half_nelson2, half_nelson3, caps_to_root,
    american_sign_language, pktcdvd, video4linux, memodipper, semtex, perf_swevent, msr, timeoutpwn, rawmodePTY
]


def get_exploits(kernel_version, is_partial, is_download, exp_name):
    if is_partial:
        regex = kernel_version + r'\.\d+'
    else:
        regex = kernel_version
    prog = re.compile(regex)
    if exp_name:
        for exploit in exploits:
            if exploit['Name'] == exp_name:
                print_exploit(exploit)
                return
    for exploit in exploits:
        if prog.search(str(exploit['Kernel'])):
            print_exploit(exploit)
            if is_download:
                url = exploit['Source']
                download_exp(url, exploit['Name'], kernel_version)


def download_exp(url, name, kernel_version):
    if 'exploit-db' in url:
        down_url = url.replace('exploits', 'download')
    else:
        down_url = url
    dir_name = 'exploits_' + kernel_version
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    try:
        urllib.urlretrieve(down_url, name)
        filename = add_suffix(name)
        shutil.move(filename, dir_name)
    except Exception, e:
        print '[-] Download {name} failed'.format(name=name)


def add_suffix(file):
    suffix = file_type(file)
    filename = file + suffix
    shutil.move(file, filename)
    return filename


def file_type(path):
    content = file(path).read()
    if '#include' in content:
        suffix = '.c'
    elif 'python' in content:
        suffix = '.py'
    elif 'perl' in content:
        suffix = '.pl'
    else:
        suffix = '.txt'
    return suffix


def print_exploit(exploit):
    print '[+] ' + exploit['Name']
    for _ in exploit:
        if _ != 'Name':
            print '    {exp}:  {content}'.format(exp=_, content=exploit[_])


def get_kernel_version():
    uname = platform.uname()
    system = uname[0]
    if system == 'Linux':
        kernel_version = uname[2]
    else:
        kernel_version = ''
        print '[-] local system is {system}!, please use -k or -n'.format(system=system)
        sys.exit(0)
    return kernel_version


def main():
    parser = OptionParser()
    parser.add_option("-k", "--kernel_version",
                      dest="kernel_version", help="kernel version number eg.2.6.8 or eg.2.6")
    parser.add_option("--download",
                      action="store_true", dest="is_download", default=False, help="download match exploits")
    parser.add_option("-n", "--name",
                      dest="exp_name", default="", help="Exploit name eg. h00lyshit")
    (options, args) = parser.parse_args()
    exp_name = options.exp_name

    if options.exp_name:
        kernel_version = ''
    elif options.kernel_version:
        kernel_version = options.kernel_version
    else:
        kernel_version = get_kernel_version()

    if re.match('\d+\.\d+\.\d+', kernel_version):
        is_partial = False
    else:
        is_partial = True
        if kernel_version[-1] == '.':
            kernel_version = kernel_version[:-1]

    if kernel_version:
        print '[*] Search Kernel {kernel}'.format(kernel=kernel_version)
    else:
        print '[*] Search Exploit {name}'.format(name=exp_name)
    print 

    get_exploits(kernel_version, is_partial, options.is_download, exp_name)

if __name__ == "__main__":
    main()
