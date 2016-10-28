#!/bin/bash

function usage {
    echo "Usage: $0 -t targets.txt [-p tcp/udp/all] [-i interface] [-n nmap-options] [-h]"
    echo "       -h: Help"
    echo "       -t: File containing ip addresses to scan. This option is required."
    echo "       -p: Protocol. Defaults to tcp"
    echo "       -i: Network interface. Defaults to eth0"
    echo "       -n: NMAP options (-A, -O, etc). Defaults to no options."
}


if [[ -z $1 ]]; then
    usage
    exit 0
fi

# commonly used default options
proto="tcp"
iface="tap0"

while getopts "p:i:t:n:h" OPT; do
    case $OPT in
        p) proto=${OPTARG};;
        i) iface=${OPTARG};;
        t) targets=${OPTARG};;
        n) nmap_opt=${OPTARG};;
        h) usage; exit 0;;
        *) usage; exit 0;;
    esac
done

if [[ -z $targets ]]; then
    echo "[!] No target file provided"
    usage
    exit 1
fi

results="/root/offsecfw/results"
nmap_opt="-n -Pn -sV -T4 -O --version-light --script=default"

while read ip; do
if [[ $proto == "tcp" || $proto == "all" ]]; then
    echo -e "Obtaining all open TCP ports using unicornscan..."
    echo "" > ${results}/${ip}/${ip}-unic-tcp.txt
    echo -e "unicornscan -i ${iface} -mT ${ip}:a -l ${results}/${ip}/${ip}-unic-tcp.txt" | tee ${results}/${ip}/${ip}-unic-tcp.txt
    unicornscan -i ${iface} -mT ${ip}:a -l ${results}/${ip}/${ip}-unic-tcp.txt
    ports=$(cat "${results}/${ip}/${ip}-unic-tcp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' |tr '\n' ',')
    if [[ ! -z $ports ]]; then
        echo -e "TCP ports for nmap to scan: $ports"
        echo -e "nmap -e ${iface} ${nmap_opt} -oA ${results}/${ip}/${ip} -p ${ports} ${ip}"
        nmap -e ${iface} ${nmap_opt} -oA ${results}/${ip}/${ip} -p ${ports} ${ip}
    else
        echo "[!] No TCP ports found"
    fi
fi

if [[ $proto == "udp" || $proto == "all" ]]; then
    echo -e "Obtaining all open UDP ports using unicornscan..."
    echo "" > ${results}/${ip}/${ip}-unic-udp.txt
    echo -e "unicornscan -i ${iface} -mU ${ip}:a -l ${results}/${ip}/${ip}-unic-udp.txt" | tee ${results}/${ip}/${ip}-unic-udp.txt
    unicornscan -i ${iface} -mU ${ip}:a -l ${results}/${ip}/${ip}-unic-udp.txt
    ports=$(cat "${results}/${ip}/${ip}-unic-udp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
    if [[ ! -z $ports ]]; then
        echo -e "UDP ports for nmap to scan: $ports"
        echo -e "nmap -e ${iface} ${nmap_opt} -sU -oA ${results}/${ip}/${ip}U -p ${ports} ${ip}"
        nmap -e ${iface} ${nmap_opt} -sU -oA ${results}/${ip}/${ip}U -p ${ports} ${ip}
    else
        echo "[!] No UDP ports found"
    fi
fi
done < ${targets}
