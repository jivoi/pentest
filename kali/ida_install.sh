#!/bin/sh
dpkg --add-architecture i386
apt-get install -y wine wine32 winbind
wine ./ida-install.exe

# IDA Pro (64-bit)
env WINEPREFIX="/root/.wine" wine-stable C:\\Program\ Files\ \(x86\)\\IDA\ X.X\\idaq64.exe

# IDA Pro (32-bit)
env WINEPREFIX="/root/.wine" wine-stable C:\\Program\ Files\ \(x86\)\\IDA\ X.X\\idaq.exe