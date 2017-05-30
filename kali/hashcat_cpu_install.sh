#!/bin/sh
apt-get install lsb-compat
# https://software.intel.com/en-us/articles/opencl-drivers#latest_CPU_runtime
# Download OpenCL™ Runtime for Intel® Core™ and Intel® Xeon® Processors for Ubuntu* (64-bit)
cd /opt
wget http://registrationcenter-download.intel.com/akdlm/irc_nas/9019/opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25.tgz
tar -xvzf opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25.tgz
./install.sh

cd /opt
# https://hashcat.net/hashcat/
wget https://hashcat.net/files/hashcat-3.5.0.7z
7z x hashcat-3.5.0.7z
/opt/hashcat-3.5.0/hashcat64.bin -I