#!/bin/bash

# Step 1
# cat targets.txt
# 192.168.81.171
# 192.168.81.182
# 192.168.81.143
# 192.168.81.119
# 192.168.81.190

# Step 2
# nmap -sV -oG scan.txt -iL targets.txt

# Step 3
# grep -v ^# scan.txt > report.txt
# scanreport.sh -f report.txt
# scanreport.sh -f report.txt -i 192.168.81.119
# scanreport.sh -f report.txt -p 3690
# scanreport.sh -f report.txt -s lighttpd

function usage {
    echo "usage: $1 [-f nmap.grepable] [-i IP] [-p port] [-s service] [-P protocol]"
}

db=""
ip=""
port=""
all=0
proto=""
while getopts "f:i:p:P:s:" OPT; do
    case $OPT in
        f) db=$OPTARG;;
        i) ip=$OPTARG;;
        p) port=$OPTARG;;
        s) service=$OPTARG;;
        P) proto=$OPTARG;;
        *) usage $0; exit;;
    esac
done

if [[ -z $db ]]; then
    # check if nmap-db.grep exists
    if [[ -f ${HOME}/nmap-db.grep ]]; then
        db=${HOME}/nmap-db.grep
    else
        usage $0
        exit
    fi
fi

if [[ ! -z $ip ]]; then # search by IP
    r=$(grep -w $ip $db | sed 's/Ports: /\n/g' |  tr '/' '\t' | tr ',' '\n' | sed 's/^ //g' | grep -v "Status: Up" | sed 's/Host:/\n\\033[0;32mHost:\\033[0;39m/g' | grep -v closed)
    echo -e "$r"

elif [[ ! -z $port ]]; then # search by port number
    r=$(grep -w $port $db | sed 's/Ports: /\n/g' |  tr '/' '\t' | tr ',' '\n' | sed 's/^ //g' | grep -v "Status: Up" | grep -e "Host: " -e ^${port} | sed 's/Host:/\n\\033[0;32mHost:\\033[0;39m/g' | grep -v closed)
    echo -e "$r"

elif [[ ! -z $service ]]; then # search by service name
    r=$(grep -w -i $service $db | sed 's/Ports: /\n/g' |  tr '/' '\t' | tr ',' '\n' | sed 's/^ //g' | grep -v "Status: Up" | grep -i -e "Host: " -e ${service} | sed 's/Host:/\n\\033[0;32mHost:\\033[0;39m/g' | grep -v closed)
    echo -e "$r"

else
    r=$(cat $db | sed 's/Ports: /\n/g' | tr '/' '\t' | tr ',' '\n' | sed 's/^ //g' | grep -v "Status: Up" | sed 's/Host:/\n\\033[0;32mHost:\\033[0;39m/g' | grep -v closed)
    echo -e "$r"
fi