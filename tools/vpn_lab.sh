#!/bin/bash

PKG="lab-openvpn"
BINDIR="/usr/sbin"
CONFIGDIR="/root/vpn_lab-connection"
CONFIG="/root/vpn_lab-connection/OS-XXX.ovpn"
PID="/tmp/vpn-lab-openvpn.pid"
LOG="/tmp/vpn-lab-openvpn.log"

case "$1" in
    start)
        printf "\nstarting: $PKG\n"
        cd $CONFIGDIR
        $BINDIR/openvpn --config $CONFIG --writepid $PID --log $LOG &
        ;;
    stop)
        printf "\nstopping: $PKG\n"
        cat $PID | xargs kill -9
        ;;
    status)
        printf "\nstatus: $PKG\n"
        ps -ef|grep openvpn
        tail $LOG
        ;;
    *)
        printf "\n\tUsage: $0 < start | stop | status >\n\n"
        ;;
esac