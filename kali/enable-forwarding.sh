#!/bin/bash
##
## enable-forwarding
## -----------------
## A simple script to forward all incoming traffic out
## whatever interface is currently connected to the Internet.
##
## Usage: enable-forwarding [Internet-connected interface]
##

if [ "$1" == "" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ] ; then
    grep -E '^## ?' "$0" | sed -E 's/^## ?//g'
    exit
fi

    
INTERFACE=$1
    
echo 1 > /proc/sys/net/ipv4/ip_forward
ufw disable
/sbin/iptables -t nat -F
/sbin/iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
    
