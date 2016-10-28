#!/bin/bash

##
## Kali Linux: Extra tools and customizations script
## =================================================
## Created by Wh1t3Rh1n0
##
## This script adds a bunch of my favorite tools to Kali Linux.
##
## Usage:
##   Install all tools:  ./Kali_Linux_Extra_Tools2.sh install
##   Non-GUI tools only: ./Kali_Linux_Extra_Tools2.sh install nogui
##

# Major changes
# * 2015-09-09: In the process of being updated for Kali 2 Light Edition.
# * 2015-11-25: More modifications. Still Kali 2 Light Edition centric.
# * 2015-12-08: Separated GUI and non-GUI tools into two sections.
# * 2016-07-14: Disabled automatic install of smbexec
# * 2016-09-17: Major changes all over


if [ "$1" == "" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    grep -E '^## ?' "$0" | sed -E 's/^## ?//g'
    exit
fi

if [ "$1" != "install" ]; then exit ; fi


# ====== Install Updates  =====================================================
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade


# ====== Personal Preferences =================================================
echo -e "\nPATH=\$PATH:/opt/pentest-scripts" >> /root/.bashrc

cat <<EOF > /root/.screenrc
caption always
caption string "%{kw}%-w%{wr}%n %t%{-}%+w"
EOF

cat <<EOF
alias nano='nano -\\\$iET 4'
>> /root/.bashrc

ln -sn /usr/share/metasploit-framework/tools/pattern_create.rb /usr/bin/pattern_create
ln -sn /usr/share/metasploit-framework/tools/pattern_offset.rb /usr/bin/pattern_offset

# Log when this script was run and with what arguments to a file
echo "$(date)> $0 $*" >> /var/log/extra-tools.log


# ====== Install GUI Tools ===================================================
if [ "$2" != "nogui" ]; then


# GUI Tools installed with apt-get
# --------------------------------

# Additions for Kali Linux 2 Light
apt-get install kali-linux-all

# Tools based on personal preference
apt-get install -y mousepad hexchat icedove
apt-get install -y vinagre

# Other stuff that comes in handy
apt-get install -y xfce4-screenshooter
apt-get install -y flashplugin-nonfree icedtea-plugin
apt-get install -y gimp
apt-get install -y libreoffice-gnome libreoffice-writer libreoffice-calc

# Fix so chromium will run as root
apt-get install -y chromium
sed -Ei "s#CHROMIUM_FLAGS=.+#CHROMIUM_FLAGS=\"--password-store=detect --user-data-dir\"#" /etc/chromium/default


# Firefox/Iceweasel Add-ons
# -------------------------
mkdir -p /opt/firefox-addons
cd /opt/firefox-addons

#Controle de Scripts
curl -L "https://addons.mozilla.org/firefox/downloads/latest/1154/addon-1154-latest.xpi" -o controle-de-scripts.xpi

#https://addons.mozilla.org/en-US/firefox/addon/open-multiple-locations/
curl -L "https://addons.mozilla.org/firefox/downloads/latest/216803/addon-216803-latest.xpi" -o open-multiple-locations.xpi

#https://addons.mozilla.org/en-US/firefox/addon/restclient/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/latest/9780/addon-9780-latest.xpi" -o restclient.xpi

#https://addons.mozilla.org/en-US/firefox/addon/refcontrol/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/latest/953/addon-953-latest.xpi" -o refcontrol.xpi

#https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/?src=ss
curl -L "https://addons.mozilla.org/firefox/downloads/file/308568/foxyproxy_standard-4.5.4-sm+tb+fx.xpi" -o foxyproxy.xpi

#https://addons.mozilla.org/en-US/firefox/addon/firebug/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/latest/1843/addon-1843-latest.xpi" -o firebug.xpi 

#https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/?src=ss
curl -L "https://addons.mozilla.org/firefox/downloads/latest/92079/addon-92079-latest.xpi" -o cookies-manager-plus.xpi

#https://addons.mozilla.org/en-US/firefox/addon/unhide-passwords/
curl -L "https://addons.mozilla.org/firefox/downloads/latest/462/addon-462-latest.xpi" -o unhide-passwords.xpi

#https://addons.mozilla.org/en-US/firefox/addon/hackbar/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/latest/3899/addon-3899-latest.xpi" -o hackbar.xpi

#https://addons.mozilla.org/en-US/firefox/addon/tamper-data/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/latest/966/addon-966-latest.xpi" -o tamper-data.xpi

#https://addons.mozilla.org/en-US/firefox/addon/quickjava/?src=search
curl -L "https://addons.mozilla.org/firefox/downloads/file/82987/quickjava-1.7.2-fx.xpi" -o quickjava.xpi

#https://addons.mozilla.org/en-US/firefox/addon/parent-folder/
curl -L "https://addons.mozilla.org/firefox/downloads/latest/1800/addon-1800-latest.xpi" -o parent-folder.xpi

#https://addons.mozilla.org/en-US/firefox/addon/user-agent-quick-switch
curl -L "https://addons.mozilla.org/firefox/downloads/latest/355807/addon-355807-latest.xpi" -o user-agent-quick-switch.xpi

#https://addons.mozilla.org/en-US/firefox/addon/email-extractor
curl -L "https://addons.mozilla.org/firefox/downloads/latest/410578/addon-410578-latest.xpi" -o email-extractor.xpi

#https://addons.mozilla.org/en-US/firefox/addon/autofill-262804/
curl -L "https://addons.mozilla.org/firefox/downloads/latest/262804/addon-262804-latest.xpi" -o autofill.xpi

#https://addons.mozilla.org/en-us/firefox/addon/checkcompatibility/
curl -L "https://addons.mozilla.org/firefox/downloads/latest/300254/addon-300254-latest.xpi" -o disable-addon-compatibility-checks.xpi


# Sublime text editor
cd /opt
if [ "$(arch)" == "x86_64" ] ; then
    wget "http://c758482.r82.cf2.rackcdn.com/Sublime%20Text%202.0.2%20x64.tar.bz2" -O sublime.tar.bz2
else
    wget "http://c758482.r82.cf2.rackcdn.com/Sublime%20Text%202.0.2.tar.bz2" -O sublime.tar.bz2
fi
tar -xjvf sublime.tar.bz2
rm -fv sublime.tar.bz2
ln -sn "/opt/Sublime Text 2/sublime_text" /usr/bin/sublime


# Old Firefox for accessing pages with weak SSL ciphers
mkdir -p /opt/firefox-old
cd /opt/firefox-old/
wget 'https://download-installer.cdn.mozilla.net/pub/firefox/releases/30.0/linux-x86_64/en-US/firefox-30.0.tar.bz2'
tar -xjvf firefox-30.0.tar.bz2
mv firefox firefox-30.0


# Firefox (not Iceweasel)
/opt/pentest-scripts/update-firefox.sh

fi


# ====== Install Non-GUI Tools ===============================================

# Setup metasploit database
apt-get install -y metasploit-framework
systemctl enable postgresql
service postgresql start
msfdb init

# Fix sendemail
# -------------
# Replaces: m{^(!?)(?:(SSL(?:v2|v3|v23|v2/3))|(TLSv1[12]?))$}i
# With:     m{^(!?)(?:(SSL(?:v2|v3|v23|v2/3))|(TLSv1[12]?))}i
sed -Ei 's#m\{\^\(\!\?\)\(\?:\(SSL\(\?:v2\|v3\|v23\|v2/3\)\)\|\(TLSv1\[12\]\?\)\)\$\}i#m\{\^\(\!\?\)\(\?:\(SSL\(\?:v2\|v3\|v23\|v2/3\)\)\|\(TLSv1\[12\]\?\)\)\}i#g' /usr/share/perl5/IO/Socket/SSL.pm


# Non-GUI Tools installed with apt-get
# ------------------------------------
apt-get install -y cifs-utils sshfs exif exiv2 exfat-fuse exfat-utils
apt-get install -y metagoofil ufw
apt-get install -y vncsnapshot
apt-get install -y xdotool
apt-get install -y dnsutils passing-the-hash creddump

# Install tools for creating a wireless access point
apt-get install -y dnsmasq hostapd-wpe
systemctl disable dnsmasq
systemctl disable hostapd-wpe

# Default passwords list:
mkdir -p /usr/share/wordlists
cd /usr/share/wordlists
wget "http://www.phenoelit.org/dpl/dpl.html" -O /usr/share/wordlists/dpl.html


# Scripted, non-apt-get installs
# ------------------------------

# progress
cd /opt
git clone https://github.com/Xfennec/progress
cd progress/
apt-get -y install libncurses5-dev
make
make install

# John The Ripper Jumbo with Tools
cd /opt
git clone https://github.com/magnumripper/JohnTheRipper

# LaZagne - Password recovery for Windows and Linux
cd /opt
git clone https://github.com/AlessandroZ/LaZagne
LAZAGNE_CURRENT=$(curl -Is 'https://github.com/AlessandroZ/LaZagne/releases/latest' | grep -E '^Location:' | awk -F '/tag/' '{print $2}' | tr -d '\r' | tr -d '\n') 
wget "https://github.com/AlessandroZ/LaZagne/releases/download/$LAZAGNE_CURRENT/Windows.zip"

# PACK - Password Analysis and Cracking Kit
cd /opt
git clone https://github.com/tomato42/pack
ln -sn /opt/pack/rulegen.py /usr/bin/pack-rulegen
ln -sn /opt/pack/statsgen.py /usr/bin/pack-statsgen
ln -sn /opt/pack/policygen.py /usr/bin/pack-policygen
ln -sn /opt/pack/maskgen.py /usr/bin/pack-maskgen

# xwatchwin
cd /opt
wget "http://www.ibiblio.org/pub/X11/contrib/utilities/xwatchwin.tar.gz"
tar -xzvf xwatchwin.tar.gz
rm xwatchwin.tar.gz
cd xwatchwin
apt-get -y install xutils-dev
xmkmf
make

# MS15-034 Check
mkdir /opt/ms15-034
cd /opt/ms15-034
ln -sn /usr/share/exploitdb/platforms/windows/dos/36773.c ms15-034.c
gcc ms15-034.c -o ms15-034

# MS14-066 Check
mkdir /opt/ms14-066
cd /opt/ms14-066
curl -L "https://raw.githubusercontent.com/anexia-it/winshock-test/master/winshock_test.sh" -o "winshock_test.sh"
cat winshock_test.sh | sed -E 's/REMOTE_VERSION=.+/REMOTE_VERSION=\$VERSION/g' | sed 's#cat <<IMP#cat <<WARN > /dev/null#g' | sed -E 's/read -p.+/REPLY=y/g' | sed 's#cat <<EOF#cat <<EOF > /dev/null#g' > winshock_test2.sh

# masscan - Mass IP port scanner
cd /opt
git clone https://github.com/robertdavidgraham/masscan
cd masscan/
apt-get -y install libpcap0.8-dev
make -j

# xwd
cd /opt
wget "http://xorg.freedesktop.org/archive/individual/app/xwd-1.0.5.tar.bz2"
tar -xjvf xwd-1.0.5.tar.bz2
rm xwd-1.0.5.tar.bz2
cd xwd-1.0.5
apt-get install -y libx11-dev libxt-dev
./configure ; make ; make install

# TCP Ping
cd /usr/bin
wget "http://www.vdberg.org/~richard/tcpping"
chmod 755 tcpping
ln -sn /usr/bin/tcpping /usr/bin/tcping

# merger.py -> nessus-merger.py
wget "https://gist.githubusercontent.com/mastahyeti/2720173/raw" -O /tmp/merger.py
echo \#\!/usr/bin/env python > /usr/bin/nessus-merger.py
cat /tmp/merger.py >> /usr/bin/nessus-merger.py
chmod 755 /usr/bin/nessus-merger.py
rm /tmp/merger.py

# VNCpwd - VNC Password Decrypter
mkdir /opt/vncpwd
cd /opt/vncpwd
wget "http://aluigi.altervista.org/pwdrec/vncpwd.zip"
unzip vncpwd.zip

# PCredz - credentials/hash/credit card number sniffer
apt-get -y remove python-pypcap && apt-get -y install python-libpcap
cd /opt
git clone https://github.com/lgandx/PCredz

# Linux Kernel Exploit Suggester
cd /opt
git clone https://github.com/PenturaLabs/Linux_Exploit_Suggester

# Responder
cd /opt
git clone https://github.com/Spiderlabs/Responder

# clusterd.py
cd /opt
git clone https://github.com/hatRiot/clusterd.git

# F5 BIG-IP Cookie decoder
mkdir /opt/BIG-IP
cd /opt/BIG-IP
wget http://www.taddong.com/tools/BIG-IP_cookie_decoder.zip
unzip BIG-IP_cookie_decoder.zip
echo -e "#\!/bin/bash\npython /opt/BIG-IP/BIG-IP_cookie_decoder.py \$(curl -i -k \$1 2>/dev/null | grep -i \"Set-Cookie: BIGip\" | cut -d ' ' -f 2 | tr -d ';' | cut -d '=' -f 2)" > /opt/BIG-IP/big-ip-url.sh

# Various extra Windows binaries
mkdir /opt/windows-extras
cd /opt/windows-extras
wget http://www.tightvnc.com/download/1.3.10/tightvnc-1.3.10_x86.zip
wget http://download.sysinternals.com/files/PSTools.zip
wget http://download.sysinternals.com/files/AccessChk.zip

# smbexec - Download only. Install is manual.
cd /opt
git clone https://github.com/pentestgeek/smbexec

# Metasploit-Plugins from darkoperator - includes the pentest plugin
cd /opt
git clone https://github.com/darkoperator/Metasploit-Plugins
#ln -sn /opt/Metasploit-Plugins/*.rb /usr/share/metasploit-framework/plugins/

# Java Deserialization Exploits
cd /opt
git clone https://github.com/CoalfireLabs/java_deserialization_exploits

# getroot.tgz from iKat
cd /opt
mkdir ikat
cd ikat
wget 'http://ikat.ha.cked.net/Linux/files/getroot.tgz'


# ====== Clean up =============================================================
apt-get --purge -y autoremove
apt-get clean


# ====== Old stuff I've disabled but am keeping around for reference ==========
# # Setup limited user for running Firefox
# cd /opt/pentest-scripts
# script_name=firefox-nonroot iw_user=firefox-user program_description="Firefox (Non-Root)"  command_line="/opt/firefox/firefox" icon="/opt/firefox/browser/icons/mozicon128.png"  catagories="Network;" ./setup-x-limited.sh 

# # Setup limited user for running Chromium
# cd /opt/pentest-scripts
# script_name=chromium-nonroot iw_user=chromium-user program_description="Chromium (Non-Root)"  command_line="/usr/bin/chromium" icon="chromium"  catagories="Network;" ./setup-x-limited.sh

# # Setup limited user for running Hexchat
# cd /opt/pentest-scripts
# script_name=hexchat-nonroot iw_user=hexchat-user program_description="Hexchat (Non-Root)" command_line=/usr/bin/hexchat icon="hexchat" catagories="Network;" ./setup-x-limited.sh

