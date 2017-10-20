#!/bin/bash
# 1 - Install docker
# https://github.com/jivoi/pentest/blob/master/kali/docker_install.sh

# 2 - Pull and run kali with docker
docker pull kalilinux/kali-linux-docker
docker run -t -i kalilinux/kali-linux-docker /bin/bash
apt-get update && apt-get install -y unicornscan nmap
# docker ps

# 3 - Commit changes
docker commit 75e9024f64c9 kali-linux-docker

# 4 - Run new docker with nmap and unicornscan
docker run --rm --name kali-nmap -it -v /root:/root kalilinux/kali-linux-docker /bin/bash

# 5 - Scan your targets
git clone https://github.com/jivoi/pentest.git ./offsecfw && cd offsecfw
mix_ping_sweep.py 192.168.56.1-254 ./results
mix_port_scan.sh -t ./results/targets.txt -p all -i eth0
mix_recon.py ./results/targets.txt