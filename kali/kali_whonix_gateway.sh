#!/bin/sh

# about:config
# media.peerconnection.enabled = false
# geo.enabled = false
# browser.send_pings = false
# browser.safebrowsing.enabled = false
# browser.safebrowsing.malware.enabled = false
# browser.search.suggest.enabled = false

echo "Etc/UTC" > /etc/timezone
cp "/usr/share/zoneinfo/Etc/UTC" "/etc/localtime"

echo "net.ipv4.tcp_timestamps = 0" > /etc/sysctl.d/tcp_timestamps.conf

cat > /etc/network/interfaces <<'_EOF'
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback
_EOF

cat > /etc/network/interfaces.d/eth0 <<'_EOF'
auto eth0
iface eth0 inet static
       ## Increment last octet of address
       ## on optional additional workstations.
       address 10.152.152.1X
       netmask 255.255.192.0
       gateway 10.152.152.10
_EOF

# cat > /etc/network/interfaces.d/eth0 <<'_EOF'
# auto eth0
# iface eth0 inet dhcp
# _EOF

cat > /etc/network/interfaces.d/eth1 <<'_EOF'
auto eth1
iface eth1 inet dhcp
_EOF

cp /etc/resolv.conf /etc/resolv.conf.$(date +"%Y%m%d_%H%M%S")
chattr -i /etc/resolv.conf

cat > /etc/resolv.conf <<'_EOF'
nameserver 10.152.152.10
_EOF

chattr +i /etc/resolv.conf

/etc/init.d/networking restart

# Proxychains configuration
cat > /etc/proxychains.conf  <<'_EOF'
strict_chain
proxy_dns
quiet_mode
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
#socks4 127.0.0.1 9050
socks4 10.152.152.10 9050
_EOF

# proxychains nmap -v -n -Pn -sT -sV -O --top-ports 100 127.0.0.1