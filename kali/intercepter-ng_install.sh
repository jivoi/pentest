#!/bin/bash
# How to install Intercepter-NG in Kali Linux
dpkg --add-architecture i386
apt update
apt install -y wine32
wine --config

mkdir /root/build && cd /root/build
wget https://github.com/intercepter-ng/mirror/blob/master/wine_pcap_dlls.tar.gz?raw=true -O wine_pcap_dlls.tar.gz
apt install -y libpcap-dev tcpdump:i386 winetricks
tar xvzf wine_pcap_dlls.tar.gz
cp wpcap/wpcap.dll.so /usr/lib/i386-linux-gnu/wine
cp packet/packet.dll.so /usr/lib/i386-linux-gnu/wine
rm -rf wine_pcap_dlls.tar.gz wpcap/ packet/
winetricks cc580
ethtool --offload eth0 rx off tx off

#
mkdir /opt/intercepter-ng && cd /opt/intercepter-ng
wget https://github.com/intercepter-ng/mirror/blob/master/Intercepter-NG.v1.0.zip?raw=true -O Intercepter-NG.zip
unzip Intercepter-NG.zip
rm -f wpcap.dll Packet.dll
wine Intercepter-NG.exe