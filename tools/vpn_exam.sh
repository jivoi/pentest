#!/bin/bash
# Exam Connection
# tar xvfj exam-connection.tar.bz2
PKG="exam-openvpn"
BINDIR="/usr/sbin"
CONFIGDIR="/root/exam-connection"
CONFIG="/root/exam-connection/OS-XXX.ovpn"
PID="/tmp/vpn-exam-openvpn.pid"
LOG="/tmp/vpn-exam-openvpn.log"

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