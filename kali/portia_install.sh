#!/bin/sh
# Finding your way to domain admin access—and even so, the game isn't over yet
# Video
# https://www.phdays.com/broadcast/
# Slides
# https://docs.google.com/presentation/d/1x_1bjCCD5hwJFWzlHM0lEPOHdWUlfYgjkUYBtdBFEmM/pub?start=false&loop=false&delayms=3000&slide=id.p4

apt-get update
apt-get install -y autoconf automake autopoint libtool pkg-config virtualenv

virtualenv -p python2 portia
source portia/bin/activate
pip install pysmb tabulate termcolor xmltodict pyasn1 pycrypto pyOpenSSL dnspython netaddr

ln -sf /opt /pentest

cd /opt
git clone https://github.com/CoreSecurity/impacket
python setup.py install

cd /opt
git clone https://github.com/libyal/libesedb.git && cd libesedb
./synclibs.sh
./autogen.sh

cd /opt
git clone https://github.com/csababarta/ntdsxtract && cd ntdsxtract
python setup.py install

cd /opt
git clone https://github.com/milo2012/portia.git && cd portia
./portia.py

# usage: PROG [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-L] [-M MODULE]
#             [-o MODULE_OPTION [MODULE_OPTION ...]] [-D]
#             [target [target ...]]

# positional arguments:
#   target                The target IP(s), range(s) or file(s) containing a
#                         list of targets

# optional arguments:
#   -h, --help            show this help message and exit
#   -d DOMAIN             Domain Name
#   -u USERNAME           Username
#   -p PASSWORD           Password
#   -L, --list-modules    List available modules
#   -M MODULE, --module MODULE
#                         Payload module to use
#   -o MODULE_OPTION [MODULE_OPTION ...]
#                         Payload module options
#   -D, --debug           Verbose mode
