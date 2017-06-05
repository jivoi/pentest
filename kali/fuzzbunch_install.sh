#!/bin/sh
# NSA FuzzBunch Framework Installation
cd /opt
git clone https://github.com/fuzzbunch/fuzzbunch.git
apt-get update
apt-get -y upgrade
apt-get install -y wine winbind
dpkg --add-architecture i386
apt-get install -y wine32

# Need X Server session
winecfg
# TO HKEY_CURRENT_USER -> Environment
# Add PATH variable C:\\windows;\C:\\windows\system;C:\\Python26;C:\\nsa\windows\fuzzbunch
wine regedit.exe
mkdir -p ~/.wine/drive_c/nsa/windows
cd ~/.wine/drive_c/nsa/windows
cp -R /opt/fuzzbunch ./
wget -O /opt/python-2.6.msi https://www.python.org/ftp/python/2.6/python-2.6.msi
wget -O /opt/pywin32-219.win32-py2.6.exe "http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20219/pywin32-219.win32-py2.6.exe?r=&ts=1493192168&use_mirror=netcologne"
wine msiexec /i /opt/python-2.6.msi
wine /opt/pywin32-219.win32-py2.6.exe
wine cmd.exe
python C:\Python26\Scripts\pywin32_postinstall.py -install
cd C:\nsa\windows\fuzzbunch
mkdir listeningposts
python fb.py

# wine c:\\python26\\python .wine/drive_c/nsa/windows/fuzzbunch/fb.py

# C:\nsa\windows\fuzzbunch>python fb.py
# --[ Version 3.5.1
# [*] Loading Plugins
# [*] Initializing Fuzzbunch v3.5.1
# [*] Adding Global Variables
# [+] Set ResourcesDir => D:\DSZOPSDISK\Resources
# [+] Set Color => True
# [+] Set ShowHiddenParameters => False
# [+] Set NetworkTimeout => 60
# [+] Set LogDir => D:\logs
# [*] Autorun ON

# use Eternalblue
# use DoublePulsar

# To protect Windows Server
# netsh advfirewall firewall add rule dir=in action=block protocol=TCP localport=135 name="Block_TCP-135"
# netsh advfirewall firewall add rule dir=in action=block protocol=TCP localport=445 name="Block_TCP-445"

# GUI for FuzzBunch
http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html
tar -xvf jre-8u131-windows-i586.tar.gz
mv jre1.8.0_131 ~/.wine/drive_c/
# add to PATH : C:\jre1.8.0_131\bin;C:\jre1.8.0_131\lib;C:\jre1.8.0_131
wine regedit

cat > ~/.wine/drive_c/nsa/windows/fuzzbunch/FUZZBUNCH-GUI.bat <<'_EOF'
c:
cd c:\nsa\windows\fuzzbunch
java -jar Start.jar
_EOF

alias nsa-gui="wine cmd < ~/.wine/drive_c/nsa/windows/fuzzbunch/FUZZBUNCH-GUI.bat"

# fuzzbunch_wrapper
# cd /opt/fuzzbunch
# git clone https://github.com/nopernik/fuzzbunch_wrapper.git