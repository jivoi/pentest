#!/bin/bash

function usage {
    echo "Usage: $0 <ip address>"
}

if [[ -z $1 ]]; then
    usage
    exit 0
fi

ip=$1
results="/root/offsecfw/results"
echo "[+] Obtaining 1-100 open TCP ports using nc..."
echo "[+] nc -nv -z -w2 $ip 1-100 | tee ${results}/${ip}/${ip}-nc-tcp-txt"

nc -nv -z -w1 $ip 1-100 | tee "${results}/${$}/${ip}-nc-tcp-txt" 2>&1