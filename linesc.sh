#!/bin/bash
#
# A script designed to help aid in the process of escalating a user privalage to root!
#
# Usage = ./LinEsc
#

## Setting Coloured variables
red=`echo -e "\033[31m"`
lcyan=`echo -e "\033[36m"`
yellow=`echo -e "\033[33m"`
green=`echo -e "\033[32m"`
blue=`echo -e "\033[34m"`
purple=`echo -e "\033[35m"`
normal=`echo -e "\033[m"`
 

# Check that the user isnt  already root or running script as root
sudo_check () {
	if [ "$(id -u)" == "0" ]; then
   		echo "$green You  already have root access! :D$normal" 1>&2
   		exit 1
   		echo ""
	fi
}

info () {
			echo "$yellow Current User$normal :  `whoami`"
			echo "$yellow uid/gid/group$normal:	 `id 2>/dev/null`"
			echo "$yellow System  Info$normal :  `uname -a`"
			echo "$yellow Distribution$normal :  `cat /etc/issue`"
			echo "$yellow Hostname $normal    :	 `hostname`"
			echo ""			
}

# Check to see what sudo access the user has been granted
sudo_script_access  () {
						CAN_I_RUN_SUDO=$(sudo -n uptime 2>&1|grep "load"|wc -l)
						if [ ${CAN_I_RUN_SUDO} -gt 0 ]; then
							if  sudo -l  | grep "may run the following commands on this host" 2>/dev/null;  then
								echo "This user has access to $green"
								sudo -l | grep root
								echo "$normal"
							fi
						else
							echo "$red  Current user has no sudo access$normal"
							echo ""
						fi	
}

# Check for suid files
suid () {		
			if  find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl'  ; then
				echo "$yellow  Possibly  interesting suid files: $green"
				find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl'
				echo "$normal"
			fi
				echo "$yellow uid files found$normal"
				find / -xdev \( -perm -4000 \) -type f -print0 2>/dev/null | xargs -0 ls -l
		  		echo ""
		}

# Check for world writable and executable files
wre () {
			echo "$yellow world writable & executable files found$normal"
			find / -perm -0002  -type f 2>/dev/null | grep -vE 'proc'
			echo " "
       }

# Check /etc/passwd for passwords
passwd () {
			passwd_check=$(cat /etc/passwd | cut -d : -f 2 |  grep  -vE 'x' | wc -l)
				if [ ${passwd_check} -gt 0 ]; then
					echo "$yellow Possible password(s) found in /etc/passwd$green"
					grep `cat /etc/passwd | cut -d : -f 2 |  grep  -w -vE 'x'` /etc/passwd
					echo "$normal"
				fi
}

file_access () {
echo ""

}



# Run the script
sudo_check
info
sudo_script_access
suid
wre
passwd
