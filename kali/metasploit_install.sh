#!/bin/sh
# Metasploit-Framework Installation

apt-get update
apt-get install -y postgresql
cd /opt
wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run
chmod +x ./metasploit-latest-linux-x64-installer.run
./metasploit-latest-linux-x64-installer.ru
chmod 775 /opt/metasploit/apps/pro/ui/config/database.yml
service postgresql start
service metasploit start
# msfconsole
# db_status