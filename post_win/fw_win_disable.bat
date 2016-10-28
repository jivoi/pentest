rem This article explains how you can quickly Turn Windows Firewall On or Off. This tips applies to Windows Vista, Windows 7 and Windows Server 2008 only!

rem Windows Firewall on computers running Windows Vista, Windows 7 and Windows Server 2008 is enabled by default. You may need turn it off for various reasons.

rem This is how you do it using a command prompt:

rem To Turn Off:
NetSh Advfirewall set allprofiles state off

rem To Turn On:
rem NetSh Advfirewall set allrprofiles state on

rem To check the status of Windows Firewall:
rem Netsh Advfirewall show allprofiles