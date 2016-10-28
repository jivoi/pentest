#!/bin/bash

# Step 1
# cat lab.txt
# 192.168.1.144
# 192.168.1.179
# 192.168.1.182

# Step 2
# ./onetwopunch.sh -t ./lab.txt -p tcp


function usage {
    echo "Usage: $0 -t targets.txt [-p tcp/udp/all] [-i interface] [-n nmap-options] [-h]"
    echo "       -h: Help"
    echo "       -t: File containing ip addresses to scan. This option is required."
    echo "       -p: Protocol. Defaults to tcp"
    echo "       -i: Network interface. Defaults to eth0"
    echo "       -n: NMAP options (-A, -O, etc). Defaults to no options."
}


if [[ ! $(id -u) == 0 ]]; then
    echo "[!] This script must be run as root"
    exit 1
fi

if [[ -z $(which nmap) ]]; then
    echo "[!] Unable to find nmap. Install it and make sure it's in your PATH   environment"
    exit 1
fi

if [[ -z $(which unicornscan) ]]; then
    echo "[!] Unable to find unicornscan. Install it and make sure it's in your PATH environment"
    exit 1
fi

if [[ -z $1 ]]; then
    usage
    exit 0
fi

# commonly used default options
proto="tcp"
iface="eth0"
nmap_opt="-sV"
targets=""

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

if [[ ${proto} != "tcp" && ${proto} != "udp" && ${proto} != "all" ]]; then
    echo "[!] Unsupported protocol"
    usage
    exit 1
fi

echo "[+] Protocol : ${proto}"
echo "[+] Interface: ${iface}"
echo "[+] Nmap opts: ${nmap_opt}"
echo "[+] Targets  : ${targets}"


# backup any old scans before we start a new one
mydir=$(dirname $0)
mkdir -p "${mydir}/backup/"
if [[ -d "${mydir}/ndir/" ]]; then
    mv "${mydir}/ndir/" "${mydir}/backup/ndir-$(date "+%Y%m%d-%H%M%S")/"
fi
if [[ -d "${mydir}/udir/" ]]; then
    mv "${mydir}/udir/" "${mydir}/backup/udir-$(date "+%Y%m%d-%H%M%S")/"
fi

rm -rf "${mydir}/ndir/"
mkdir -p "${mydir}/ndir/"
rm -rf "${mydir}/udir/"
mkdir -p "${mydir}/udir/"

while read ip; do
    echo "[+] Scanning $ip for $proto ports..."

    # unicornscan identifies all open TCP ports
    if [[ $proto == "tcp" || $proto == "all" ]]; then
        echo "[+] Obtaining all open TCP ports using unicornscan..."
        echo "[+] unicornscan -i ${iface} -mT ${ip}:a -l ${mydir}/udir/${ip}-tcp.txt"
        unicornscan -i ${iface} -mT ${ip}:a -l ${mydir}/udir/${ip}-tcp.txt
        ports=$(cat "${mydir}/udir/${ip}-tcp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
        if [[ ! -z $ports ]]; then
            # nmap follows up
            echo "[+] Ports for nmap to scan: $ports"
            echo "[+] nmap -e ${iface} ${nmap_opt} -oX ${mydir}/ndir/${ip}-tcp.xml -oG ${mydir}/ndir/${ip}-tcp.grep -p ${ports} ${ip}"
            nmap -e ${iface} ${nmap_opt} -oX ${mydir}/ndir/${ip}-tcp.xml -oG ${mydir}/ndir/${ip}-tcp.grep -p ${ports} ${ip}
        else
            echo "[!] No TCP ports found"
        fi
    fi

    # unicornscan identifies all open UDP ports
    if [[ $proto == "udp" || $proto == "all" ]]; then
        echo "[+] Obtaining all open UDP ports using unicornscan..."
        echo "[+] unicornscan -i ${iface} -mU ${ip}:a -l ${mydir}/udir/${ip}-udp.txt"
        unicornscan -i ${iface} -mU ${ip}:a -l ${mydir}/udir/${ip}-udp.txt
        ports=$(cat "${mydir}/udir/${ip}-udp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
        if [[ ! -z $ports ]]; then
            # nmap follows up
            echo "[+] nmap -e ${iface} ${nmap_opt} -sU -oX ${mydir}/ndir/${ip}-udp.xml -oG ${mydir}/ndir/${ip}-udp.grep -p ${ports} ${ip}"
            nmap -e ${iface} ${nmap_opt} -sU -oX ${mydir}/ndir/${ip}-udp.xml -oG ${mydir}/ndir/${ip}-udp.grep -p ${ports} ${ip}
        else
            echo "[!] No UDP ports found"
        fi
    fi
done < ${targets}

echo "[+] Scans completed"
