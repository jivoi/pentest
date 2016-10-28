echo ::SYSTEM REPORT::
echo ::SYSTEMINFO:: > all_info.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> all_info.txt
echo ::HOSTNAME:: >> all_info.txt
hostname >> all_info.txt
echo ::USERNAME:: >> all_info.txt
echo %username% >> all_info.txt
echo ::ALL USERS:: >> all_info.txt
net users  >> all_info.txt
echo ::IPCONFIG:: >> all_info.txt
ipconfig /all  >> all_info.txt
echo ::ROUTE:: >> all_info.txt
route print >> all_info.txt
echo ::ARP:: >> all_info.txt
arp -A >> all_info.txt
echo ::NETSTAT:: >> all_info.txt
netstat -ano >> all_info.txt
echo ::FWSTATE:: >> all_info.txt
netsh firewall show state >> all_info.txt
netsh firewall show config >> all_info.txt
echo ::SCHEDULED TASKS:: >> all_info.txt
schtasks /query /fo LIST /v >> all_info.txt
echo ::RUNNING PROC:: >> all_info.txt
tasklist /SVC >> all_info.txt
echo ::STARTED SVC:: >> all_info.txt
net start  >> all_info.txt
echo ::WMI SVC::  >> all_info.txt
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """  >> all_info.txt
echo ::DRIVERS:: >> all_info.txt
DRIVERQUERY >> all_info.txt
echo ::PATCHES:: >> all_info.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn >> all_info.txt
echo ::CONFIG FILES:: >> all_info.txt
copy c:\sysprep.inf all_info_sysprep.inf
copy c:\sysprep\sysprep.xml  all_info_sysprep.xml
copy %WINDIR%\Panther\Unattend\Unattended.xml all_info_Unattended.xml
copy %WINDIR%\Panther\Unattended.xml all_info_Unattended2.xml
echo ::ALWAYS ELEVATED HKLM:: >> all_info.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> all_info.txt
echo ::ALWAYS ELEVATED HKCU:: >> all_info.txt
reg query reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> all_info.txt
echo ::FILES WITH PW:: >> all_info.txt
dir /s *pass* == *cred* == *vnc* == *.config* >> all_info.txt
findstr /si password *.xml *.ini *.txt >> all_info.txt
echo ::REG WITH PW:: >> all_info.txt
reg query HKLM /f password /t REG_SZ /s >> all_info.txt
reg query HKCU /f password /t REG_SZ /s >> all_info.txt
echo ::CHECK SPOOL SVC:: >> all_info.txt
sc qc Spooler  >> all_info.txt
echo ::ACCESS CHK:: >> all_info.txt
accesschk.exe /accepteula -ucqv Spooler  >> all_info.txt
accesschk.exe /accepteula -uwcqv "Authenticated Users" *  >> all_info.txt
echo ::CHECK UPNP SVC:: >> all_info.txt
sc qc upnphost >> all_info.txt
echo ::PATHS DURING BOOT:: >> all_info.txt
echo %path%  >> all_info.txt