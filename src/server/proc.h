#ifndef __SPLINTER_PROC__
#define __SPLINTER_PROC__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

FILE* popen2(const char* command, const char* type, int *pid);
int pclose2(FILE* fp, pid_t pid);

#endif
