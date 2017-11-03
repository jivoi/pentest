#!/bin/sh
# How to install Node.js in Kali Linux

src=$(mktemp -d) && cd $src
apt-get install -y python g++ make checkinstall fakeroot
wget -N http://nodejs.org/dist/node-latest.tar.gz
tar xzvf node-latest.tar.gz && cd node-v*
./configure
fakeroot checkinstall -y --install=no --pkgversion $(echo $(pwd) | sed -n -re's/.+node-v(.+)$/\1/p') make -j$(($(nproc)+1)) install
# dpkg -i
# node -v

# https://github.com/npm/npm
# curl -L https://www.npmjs.com/install.sh | sh
# npm install -g sql-cli
