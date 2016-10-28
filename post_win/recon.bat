@ECHO OFF
echo Systeminfo "systeminfo.txt" >> recon.txt
systeminfo >> systeminfo.txt
echo ################################################## | more >> recon.txt 
echo type systeminfo.txt | findstr /B /C:"OS Name" /C:"OS Version" | more >> recon.txt
type systeminfo.txt | findstr /B /C:"OS Name" /C:"OS Version" | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo hostname | more >> recon.txt
hostname | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo whoami | more >> recon.txt
whoami | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo net users | more >> recon.txt
net users | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo net user %username% | more >> recon.txt
net user %username% | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo dir C:\Windows\repair\ >> recon.txt
dir C:\Windows\repair\ >> recon.txt
echo ################################################## | more >> recon.txt 
echo ipconfig /all | more >> recon.txt
ipconfig /all | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo route print | more >> recon.txt
route print | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo arp -A | more >> recon.txt
arp -A | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo netstat -ano | more >> recon.txt
netstat -ano | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo netsh firewall show state | more >> recon.txt
netsh firewall show state | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo netsh firewall show config | more >> recon.txt
netsh firewall show config | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo schtasks /query /fo LIST /v | more >> recon.txt
schtasks /query /fo LIST /v | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo tasklist /SVC | more >> recon.txt
tasklist /SVC | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo net start | more >> recon.txt
net start | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo DRIVERQUERY | more >> recon.txt
DRIVERQUERY | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo reg query HKLM /f password /t REG_SZ /s | more >> recon.txt
reg query HKLM /f password /t REG_SZ /s | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo reg query HKCU /f password /t REG_SZ /s | more >> recon.txt
reg query HKCU /f password /t REG_SZ /s | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated | more >> recon.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated | more >> recon.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated | more >> recon.txt
IF EXIST accesschk.exe (
        echo ################################################## | more >> recon.txt 
        echo accesschk.exe /accepteula -uwcqv "Authenticated Users" * | more >> recon.txt
        accesschk.exe /accepteula -uwcqv "Authenticated Users" * | more >> recon.txt
) ELSE (
        echo ################################################## | more >> recon.txt 
        echo ACCESSCHK.EXE not found!! | more >> recon.txt
        echo ACCESSCHK.EXE not found!! 
)
echo ################################################## | more >> recon.txt 
echo wmic | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic process get CSName,Description,ExecutablePath,ProcessId  | more >> recon.txt
wmic process get CSName,Description,ExecutablePath,ProcessId  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName  | more >> recon.txt
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName  | more >> recon.txt
::echo ################################################## | more >> recon.txt
::set command=('echo wmic service get name,displayname,pathname,startmode \|findstr /i "Auto" \|findstr /i /v "C:\Windows\\" \|findstr /i /v """')
::FOR /F "tokens=*" %a in ('wmic service get name,displayname,pathname,startmode \| findstr /i "Auto" \| findstr /i /v "C:\Windows\\" \| findstr /i /v """') do SET OUTPUT=%a
::echo %command% | more >> recon.txt
::echo %output% | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic USERACCOUNT list full  | more >> recon.txt
wmic USERACCOUNT list full  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic group list full  | more >> recon.txt
wmic group list full  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress  | more >> recon.txt
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace  | more >> recon.txt
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic netuse list full  | more >> recon.txt
wmic netuse list full  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic qfe get Caption,Description,HotFixID,InstalledOn  | more >> recon.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic startup get Caption,Command,Location,User  | more >> recon.txt
wmic startup get Caption,Command,Location,User  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version  | more >> recon.txt
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory  | more >> recon.txt
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory  | more >> recon.txt
echo ################################################## | more >> recon.txt 
echo wmic Timezone get DaylightName,Description,StandardName  | more >> recon.txt
wmic Timezone get DaylightName,Description,StandardName  | more >> recon.txt
