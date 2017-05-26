#!/bin/sh
sudo apt-get install -y cmake build-essential libboost-dev libqt5xmlpatterns5-dev qtbase5-dev qt5-default libgraphviz-dev libqt5svg5-dev


cd /opt/
git clone --depth=50 --branch=3.0.4 https://github.com/aquynh/capstone.git
cd capstone
./make.sh
sudo ./make.sh install

cd /opt
git clone --recursive https://github.com/eteran/edb-debugger.git
cd edb-debugger
mkdir build
cd build
cmake ..
make

#./edb

