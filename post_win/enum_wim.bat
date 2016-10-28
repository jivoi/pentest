rem Description: Windows basic enumeration scrip

rem --------------------------------- Host and user details ------------------------------------------

echo 1. Finding os details > win_enum_report.txt
echo --------------------- >> win_enum_report.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 2. Finding hostname >> win_enum_report.txt
echo --------------------- >> win_enum_report.txt
hostname >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 3. Finding exploited user name >> win_enum_report.txt
echo --------------------- >> win_enum_report.txt
echo %username% >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 4. All users on the system >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net users >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 5. Getting group membership, active sessions, account lock out policy >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net user %username% >> win_enum_report.txt
net users >> win_enum_report.txt
net session  >> win_enum_report.txt
net accounts /domain  >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 5.1. Display which group policies are applied and info about the OS if victim is the member of a domain: >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
gpreport >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


rem ------------------------------------ Network details ------------------------------------------

echo 6. Checking available network interfaces and routing table >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
ipconfig /all >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 7. routing table >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
route print >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt



echo 8. Checking ARP cache table for all available interfaces >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
arp -A >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 9. Checking active network connections >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
netstat -ano >> win_enum_report.txt
netstat -an | find /i "established" >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt



echo 9.1. Checking hidden, non-hidden share  >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net share >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 9.2. list all the hosts on the "compromised host's domain" and list the domains that the compromised host can see >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net view >> win_enum_report.txt
net view /domain >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 9.3. enumerate all users on the domain >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net group "domain user" /domain
net localgroup users /domain
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt




rem ------------------------------------ Firewall details ------------------------------------------

echo 10. The netsh firewall state >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
netsh firewall show state >> win_enum_report.txt
netsh firewall show opmode >> win_enum_report.txt
netsh firewall show port >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt


echo 11. Firewall configuration >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
netsh firewall show config >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt



rem ------------------------------------ Process and service details ------------------------------------------


echo 12. Scheduled tasks >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
schtasks /query /fo LIST /v >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 13. Running processes >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
tasklist /SVC >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 13.1. System variable and paths >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
set >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 14. Started windows services >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
net start >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt

echo 15. Installed 3rd party drivers >> win_enum_report.txt
echo --------------------------- >> win_enum_report.txt
DRIVERQUERY >> win_enum_report.txt
echo. >> win_enum_report.txt
echo. >> win_enum_report.txt



