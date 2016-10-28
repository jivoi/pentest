#!/bin/bash

##
## live-usb-tweaks.sh
## ------------------
## Install tweaks to increase performance when running
## Kali from a LiveUSB with persistence.
##
## Usage: ./live-usb-tweaks.sh install
##

if [ "$1" == "" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    grep -E '^##[^#]' "$0" | sed -E 's/^## ?//g'
    exit
fi

echo "Installing LiveUSB tweaks..."

### Changes to rc.local ###

sed -i 's/exit 0//g' /etc/rc.local

cat <<EOF >> /etc/rc.local
# Limit writes to the persistent volume to every 120 seconds
mount -o remount,noatime,commit=120 /lib/live/mount/persistence/loop1

#Mount  /var/cache/apt/archives onto ramdisk 
#mkdir /dev/shm/apt-archives
#chmod 1777 /dev/shm/apt-archives
#mount --bind /dev/shm/apt-archives /var/cache/apt/archives
mount -t tmpfs tmpfs /var/cache/apt/archives -o rw,nosuid,nodev,uid=0,gid=0,mode=744
EOF

echo -e "\nexit 0" >> /etc/rc.local


### Disable rsyslog ###
#update-rc.d rsyslog disable


### Add these lines to /etc/sysctl.conf ###
cat <<EOF >> /etc/sysctl.conf
vm.swappiness = 0
vm.dirty_background_ratio = 20
vm.dirty_expire_centisecs = 0
vm.dirty_ratio = 80
vm.dirty_writeback_centisecs = 0
EOF


echo "Reboot for changes to take effect."
