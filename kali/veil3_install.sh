#!/bin/sh
# Installing Veil v3.0

apt-get -y install git
cd /opt
git clone https://github.com/Veil-Framework/Veil.git
cd Veil/setup
sudo ./setup.sh -c