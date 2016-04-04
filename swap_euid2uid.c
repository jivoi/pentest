#include <stdio.h>

void main(int argc, char *argv[]) {
  setreuid(geteuid(), getuid());
  execv("/bin/bash", argv);
}