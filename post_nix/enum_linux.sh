#!/bin/bash

echo '[-] What is the distribution type? What version?' >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/issue">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/issue >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/*-release">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/*-release >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/lsb-release">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/lsb-release >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/redhat-release">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/redhat-release >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo '[-] What is the kernel version? Is it 64-bit?' >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /proc/version">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /proc/version >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: uname -a">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
uname -a >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: uname -mrs">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
uname -mrs >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: rpm -q kernel">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
rpm -q kernel >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: dmesg | grep Linux">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
dmesg | grep Linux >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: ls /boot | grep vmlinuz-">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
ls /boot | grep vmlinuz- >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo '[-] What can be learnt from the environmental variables?' >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/profile">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/profile >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat /etc/bashrc">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat /etc/bashrc >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat ~/.bash_profile">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat ~/.bash_profile >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat ~/.bashrc">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat ~/.bashrc >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: cat ~/.bash_logout">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
cat ~/.bash_logout >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: env">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
env >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: set">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
set >>1_os_details.txt
echo ' '  >>1_os_details.txt
echo '[-] What is the printer name?' >>1_os_details.txt
echo ' ' >>1_os_details.txt
echo "[+] cmd used: lpstat -a">>1_os_details.txt
echo '[*] Result: ==========================================================================================>'  >>1_os_details.txt
lpstat -a >>1_os_details.txt
echo ' '  >>1_os_details.txt

echo '[-] Who are you? Who is logged in? Who has been logged in? Who else is there? Who can do what?' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: id">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
id >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: who">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
who >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: w">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
w >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: last">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
last >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] What sensitive files can be found?' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/passwd | cut -d:    # List of users">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/passwd | cut -d:    # List of users >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
#echo "[+] cmd used: grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
#grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
#echo "[+] cmd used: awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
#awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/sudoers">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/sudoers >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: sudo -l">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
sudo -l >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/passwd">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/passwd >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/group">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/group >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/shadow">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/shadow >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: ls -alh /var/mail/">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
ls -alh /var/mail/ >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] What are the interesting stuff in the home directorie(s)? If its possible to access' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: ls -ahlR /root/">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
ls -ahlR /root/ >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: ls -ahlR /home/">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
ls -ahlR /home/ >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] Whar are passwords in; scripts, databases, configuration files or log files? Default paths and locations for passwords' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /var/apache2/config.inc">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /var/apache2/config.inc >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /var/lib/mysql/mysql/user.MYD">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /var/lib/mysql/mysql/user.MYD >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /root/anaconda-ks.cfg">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /root/anaconda-ks.cfg >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] What has the user being doing? Is there any password in plain text? What have they been edting?' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.bash_history">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.bash_history >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.nano_history">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.nano_history >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.atftp_history">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.atftp_history >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.mysql_history">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.mysql_history >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.php_history">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.php_history >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] What user information can be found?' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.bashrc">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.bashrc >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.profile">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.profile >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /var/mail/root">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /var/mail/root >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /var/spool/mail/root">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /var/spool/mail/root >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo '[-] What private-key information can be found?' >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/authorized_keys">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/authorized_keys >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/identity.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/identity.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/identity">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/identity >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/id_rsa.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/id_rsa.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/id_rsa">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/id_rsa >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/id_dsa.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/id_dsa.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat ~/.ssh/id_dsa">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat ~/.ssh/id_dsa >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_config">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_config >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/sshd_config">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/sshd_config >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_dsa_key.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_dsa_key.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_dsa_key">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_dsa_key >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_rsa_key.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_rsa_key.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_rsa_key">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_rsa_key >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_key.pub">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_key.pub >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt
echo ' ' >>2_confidential_user_info.txt
echo "[+] cmd used: cat /etc/ssh/ssh_host_key">>2_confidential_user_info.txt
echo '[*] Result: ==========================================================================================>'  >>2_confidential_user_info.txt
cat /etc/ssh/ssh_host_key >>2_confidential_user_info.txt
echo ' '  >>2_confidential_user_info.txt

echo '[-] What are sensitive files, search- proof, network-secret,bank data, local.txt' >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name proof.txt -or -name local.txt or -name network-secret.txt">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name proof.txt -or -name local.txt -or -name network-secret.txt >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name *pass*.txt">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name *pass*.txt >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name *bank*.txt">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name *bank*.txt >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name *sensitive*.txt">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name *sensitive*.txt >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name *user*.txt">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name *user*.txt >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo '[-] What development tools/languages are installed/supported?' >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name perl*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name perl* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name python*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name python* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name gcc*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name gcc* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name cc">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name cc >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo 'How can files be uploaded?' >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name wget">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name wget >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name nc*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name nc* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name netcat*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name netcat* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name tftp*">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name tftp* >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt
echo ' ' >>3_sensitive_info.txt
echo "[+] cmd used: find / -name ftp">>3_sensitive_info.txt
echo '[*] Result: ==========================================================================================>'  >>3_sensitive_info.txt
find / -name ftp >>3_sensitive_info.txt
echo ' '  >>3_sensitive_info.txt

echo '[-] What services are running? Which service has which user privilege?' >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ps aux | grep root">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ps aux | grep root >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ps -ef | grep root">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ps -ef | grep root >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/services">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/services >>4_services.txt
echo ' '  >>4_services.txt
echo '[-] What applications are installed? What version are they? Are they currently running?' >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -alh /usr/bin/">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -alh /usr/bin/ >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -alh /sbin/">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -alh /sbin/ >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: dpkg -l">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
dpkg -l >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: rpm -qa">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
rpm -qa >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -alh /var/cache/apt/archivesO">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -alh /var/cache/apt/archivesO >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -alh /var/cache/yum/">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -alh /var/cache/yum/ >>4_services.txt
echo ' '  >>4_services.txt
echo '[-] What are the service(s) settings misconfigured? Are any (vulnerable) plugins attached?' >> 4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/syslog.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/syslog.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/chttp.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/chttp.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/lighttpd.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/lighttpd.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/cups/cupsd.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/cups/cupsd.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/inetd.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/inetd.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/apache2/apache2.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/apache2/apache2.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/my.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/my.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/httpd/conf/httpd.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/httpd/conf/httpd.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /opt/lampp/etc/httpd.conf">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /opt/lampp/etc/httpd.conf >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
#echo "[+] cmd used: ls -aRl /etc/ | awk '$1 ~ /^.*r.*/">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
#ls -aRl /etc/ | awk '$1 ~ /^.*r.*/ >>4_services.txt
echo ' '  >>4_services.txt
echo '[-] What jobs are scheduled?' >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: crontab -l">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
crontab -l >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -alh /var/spool/cron">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -alh /var/spool/cron >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -al /etc/ | grep cron">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -al /etc/ | grep cron >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: ls -al /etc/cron*">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
ls -al /etc/cron* >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/cron*">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/cron* >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/at.allow">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/at.allow >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/at.deny">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/at.deny >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/cron.allow">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/cron.allow >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/cron.deny">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/cron.deny >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/crontab">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/crontab >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /etc/anacrontab">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /etc/anacrontab >>4_services.txt
echo ' '  >>4_services.txt
echo ' ' >>4_services.txt
echo "[+] cmd used: cat /var/spool/cron/crontabs/root">>4_services.txt
echo '[*] Result: ==========================================================================================>'  >>4_services.txt
cat /var/spool/cron/crontabs/root >>4_services.txt
echo ' '  >>4_services.txt

echo ' ' >>4_services.txt
echo '[-] Which configuration files can be written in /etc/? Able to reconfigure a service?' >>5_system_details.txt
echo ' ' >>5_system_details.txt
#echo "[+] cmd used: ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
#ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
#echo "[+] cmd used: ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
#ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
#echo "[+] cmd used: ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
#ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
#echo "[+] cmd used: ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
#ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: find /etc/ -readable -type f 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
find /etc/ -readable -type f 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: find /etc/ -readable -type f -maxdepth 1 2>/dev/null">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
find /etc/ -readable -type f -maxdepth 1 2>/dev/null >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo '[-] What can be found in /var/ ?' >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/mail">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/mail >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/spool">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/spool >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/spool/lpd">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/spool/lpd >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/lib/pgsql">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/lib/pgsql >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/lib/mysql">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/lib/mysql >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/lib/dhcp3/dhclient.leases">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/lib/dhcp3/dhclient.leases >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo '[-] What are the hidden files on website? Any settings file with database information?' >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alhR /var/www/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alhR /var/www/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alhR /srv/www/htdocs/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alhR /srv/www/htdocs/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alhR /usr/local/www/apache22/data/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alhR /usr/local/www/apache22/data/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alhR /opt/lampp/htdocs/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alhR /opt/lampp/htdocs/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alhR /var/www/html/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alhR /var/www/html/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo '[-] What is there in the log file(s) (Could help with Local File Includes!)' >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /etc/httpd/logs/access_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /etc/httpd/logs/access_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /etc/httpd/logs/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /etc/httpd/logs/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /etc/httpd/logs/error_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /etc/httpd/logs/error_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /etc/httpd/logs/error.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /etc/httpd/logs/error.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache2/access_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache2/access_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache2/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache2/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache2/error_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache2/error_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache2/error.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache2/error.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache/access_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache/access_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/apache/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/apache/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/auth.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/auth.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/chttp.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/chttp.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/cups/error_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/cups/error_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/dpkg.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/dpkg.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/faillog">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/faillog >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/httpd/access_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/httpd/access_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/httpd/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/httpd/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/httpd/error_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/httpd/error_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/httpd/error.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/httpd/error.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/lastlog">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/lastlog >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/lighttpd/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/lighttpd/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/lighttpd/error.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/lighttpd/error.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/lighttpd/lighttpd.access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/lighttpd/lighttpd.access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/lighttpd/lighttpd.error.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/lighttpd/lighttpd.error.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/messages">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/messages >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/secure">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/secure >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/syslog">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/syslog >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/wtmp">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/wtmp >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/xferlog">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/xferlog >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/log/yum.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/log/yum.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/run/utmp">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/run/utmp >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/webmin/miniserv.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/webmin/miniserv.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/www/logs/access_log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/www/logs/access_log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: cat /var/www/logs/access.log">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
cat /var/www/logs/access.log >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/lib/dhcp3/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/lib/dhcp3/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/log/postgresql/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/log/postgresql/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/log/proftpd/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/log/proftpd/ >>5_system_details.txt
echo ' '  >>5_system_details.txt
echo ' ' >>5_system_details.txt
echo "[+] cmd used: ls -alh /var/log/samba/">>5_system_details.txt
echo '[*] Result: ==========================================================================================>'  >>5_system_details.txt
ls -alh /var/log/samba/ >>5_system_details.txt
echo ' '  >>5_system_details.txt

echo '[-] What are the file-systems mounted?' >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: mount">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
mount >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: df -h">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
df -h >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo 'Are there any unmounted file-systems?' >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: cat /etc/fstab">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
cat /etc/fstab >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo '[-] What Advanced Linux File Permissions are used? Sticky bits, SUID & GUID'  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -1000 -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -1000 -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -g=s -type f 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -g=s -type f 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -u=s -type f 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -u=s -type f 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -g=s -o -perm -u=s -type f 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo '[-] Where can written to and executed from? A few common places: /tmp, /var/tmp, /dev/shm' >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -writable -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -writable -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -222 -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -222 -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -o w -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -o w -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -perm -o x -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -perm -o x -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / \( -perm -o w -perm -o x \) -type d 2>/dev/null">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo 'Any problem files? Word-writeable, nobody files' >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: find /dir -xdev \( -nouser -o -nogroup \) -print">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
find /dir -xdev \( -nouser -o -nogroup \) -print >>6_mount_details.txt
echo ' '  >>6_mount_details.txt
echo ' ' >>6_mount_details.txt
echo "[+] cmd used: ">>6_mount_details.txt
echo '[*] Result: ==========================================================================================>'  >>6_mount_details.txt
 >>6_mount_details.txt
echo ' '  >>6_mount_details.txt

echo '[-] What NIC(s) does the system have? Is it connected to another network?' >>7_network_details.txt
echo ' ' >>7_network_details.txt

echo ' ' >>7_network_details.txt
echo "[+] cmd used: ifconfig -a">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
ifconfig -a >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: cat /etc/network/interfaces">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
cat /etc/network/interfaces >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: cat /etc/sysconfig/network">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
cat /etc/sysconfig/network >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo '[-] What are the network configuration settings? What can you find out about this network? DHCP server? DNS server? Gateway?' >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: cat /etc/resolv.conf">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
cat /etc/resolv.conf >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: cat /etc/sysconfig/network">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
cat /etc/sysconfig/network >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: cat /etc/networks">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
cat /etc/networks >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: iptables -L">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
iptables -L >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: hostname">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
hostname >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: dnsdomainname">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
dnsdomainname >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo '[-] What other users & hosts are communicating with the system?' >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: lsof -i">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
lsof -i >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: lsof -i :80">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
lsof -i :80 >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: grep 80 /etc/services">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
grep 80 /etc/services >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: netstat -antup">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
netstat -antup >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: netstat -antpx">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
netstat -antpx >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: netstat -tulpn">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
netstat -tulpn >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: chkconfig --list">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
chkconfig --list >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: chkconfig --list | grep 3:on">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
chkconfig --list | grep 3:on >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: last">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
last >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: w">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
w >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo '[-] Whats cached? IP and/or MAC addresses' >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: arp -e">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
arp -e >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: route">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
route >>7_network_details.txt
echo ' '  >>7_network_details.txt
echo ' ' >>7_network_details.txt
echo "[+] cmd used: /sbin/route -nee">>7_network_details.txt
echo '[*] Result: ==========================================================================================>'  >>7_network_details.txt
/sbin/route -nee >>7_network_details.txt
echo ' '  >>7_network_details.txt
