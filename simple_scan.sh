#!/bin/bash

# Perform information gathering on url
# ./simple_scan <url>

if [ "$#" -eq 1 ]; then

if [[ "$1" =~ ^www.* ]]; then
	ADRES=$( echo $1 | cut -b5- )
else
	ADRES=$1
fi

	clear
	printf "\n%s %s" "[~]" $(date +"%T")
	printf "\n[~] Target - $1"
	printf "\n[~] IP - %s" $(dig +short $1)

#Info

	printf "\n\n\e[1m[+] Basic info\e[0m\n"
	printf "\n - Host\n\n"
	host -W 3 -a $1
	printf "\n - Whois\n"
	whois $ADRES

#80

	nc -z -w5 $1 80; STATUS=$?
	if [ $STATUS -eq 0 ]; then
		printf "\n\e[1m[+] HTTP (80)\e[0m\n\n - Headers\n\n"
		curl -s -L -X GET -I $1 -m 5 -A "Mozilla/5.0 (Windows NT 5.1; rv:15.0) Gecko/20100101 Firefox/15.0.1"
		printf " - Methods\n\n"

	for method in GET POST PUT TRACE TRACK HEAD DELETE OPTIONS;
	do
	printf "$method ";
	printf "$method / HTTP/1.1\nHost: $1\n\n" | nc -q 1 $1 80 | grep "HTTP/1.1"
	done
	
	printf "\n\n - Files\n\n"
	dirb http://$1 /home/devil/Desktop/Wordlist/quickdirs.txt -a "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" -r | grep '^\+\|==>\|-->'


	else 
	printf "\n\e[1m[-] HTTP (80)\e[0m\n\n"
	fi

#443

	nc -z -w5 $1 443; STATUS=$?
	if [ $STATUS -eq 0 ]; then
		printf "\n\n\e[1m[+] HTTPS (443)\e[0m\n\n - Headers\n\n"
		curl -s -L -X GET -I $1 -m 5 -k -A "Mozilla/5.0 (Windows NT 5.1; rv:15.0) Gecko/20100101 Firefox/15.0.1"

		printf " - Methods\n\n"

	for method in GET POST PUT TRACE TRACK HEAD DELETE OPTIONS;
	do
	printf "$method ";
	printf "$method / HTTP/1.1\nHost: $1\n\n" | ncat --ssl -w 5 $1 443 | grep "HTTP/1.1"
	done

	printf "\n - SSL\n\n"; sslscan --no-colour --no-compression --no-renegotiation  --no-preferred $1 

	else 
	printf "\n\e[1m[-] HTTPS (443)\e[0m\n\n"
	fi

#Scans

	printf "\n\e[1m[+] Nmap\e[0m\n\n"
	sudo nmap -n -O -sS -T4 -Pn -sV -f -sC $1 

	printf "\n\e[1m[+] DNS\e[0m\n\n"
	printf " - fierce\n\n"
	fierce -threads 5 -dns $ADRES
	printf "\n - dnsdict6\n\n"
	dnsdict6 -4 -t 15 $ADRES

#	printf "\n\e[1m[+] Bruteforce\e[0m\n\n"
#	nmap --script brute,auth $1 | grep '^|'

#End

else
	printf "\nYou need to specify target...\n"
	printf "Usage - ./$(basename "$(test -L "$0" && readlink "$0" || echo "$0")") <url>\n\n"
fi
