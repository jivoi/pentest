#!/bin/sh
# Mana Toolkit HowTo
# /usr/share/mana-toolkit — main dir
# /usr/share/mana-toolkit/run-mana — run scripts dir
# /etc/mana-toolkit/ — config files
# /var/lib/mana-toolkit — logs

# iw list
# Supported interface modes:
#     * IBSS
#     * managed
#     * AP
#     * AP/VLAN
#     * monitor
#     * mesh point

# Main scripts
# start-nat-full.sh — start fake AP with NAT and all options (MITM)
# start-nat-simple.sh — start fake AP with NAT
# start-noupstream.sh — AP without internet access
# start-noupstream-eap.sh — AP without internet access for EAP attack

sudo apt-get install -y libcurl4-openssl-dev libssl-dev libnl-3-dev libnl-genl-3-dev
git clone --depth 1 https://github.com/sensepost/mana
cd mana
git submodule init
git submodule update
make
make install