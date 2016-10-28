#!/bin/bash 

##
## Firefox Updater/Installer
## -------------------------
## Just a simple script to update or install Firefox on Kali Linux.
##
## Installs to /opt/firefox
##
## Run with no options to install or update.
##

if [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    grep -E '^## ?' "$0" | sed -E 's/^## ?//g'
    exit
fi

# Firefox (not Iceweasel) 
# Reference: https://download-installer.cdn.mozilla.net/pub/firefox/releases/latest/README.txt
cd /opt
rm -rfv firefox

if [ "$(uname -m)" == "i686" ] ; then 
  wget -O firefox.tar.bz2 "https://download.mozilla.org/?product=firefox-latest&os=linux&lang=en-US"
else 
  wget -O firefox.tar.bz2 "https://download.mozilla.org/?product=firefox-latest&os=linux64&lang=en-US"
fi

tar -xjvf firefox.tar.bz2
rm -fv firefox.tar.bz2
