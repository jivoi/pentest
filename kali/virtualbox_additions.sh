#!/bin/sh
apt-get update
apt-get install -y virtualbox-guest-x11
apt-get install -y linux-image-amd64 linux-headers-amd64
#apt-get install -y linux-image-4.7.0-kali1-686-pae linux-headers-4.7.0-kali1-686-pae
cp -f /media/cdrom/VBoxLinuxAdditions.run /root/
chmod 755 /root/VBoxLinuxAdditions.run
cd /root
mkdir /etc/depmod.d
export KERN_DIR=/usr/src/linux-headers-4.9.0-kali3-amd64/
./VBoxLinuxAdditions.run