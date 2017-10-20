#!/bin/sh
# On Router System
systemctl get-default
systemctl set-default -f multi-user.target

# tun0 or tun1
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o tun1 -j MASQUERADE

# On Client System
ip ro add default via <ROUTER_IP> dev eth1 proto static
