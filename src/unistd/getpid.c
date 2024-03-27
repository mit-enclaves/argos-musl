#include <unistd.h>
#include "syscall.h"
#include "stdio.h"

pid_t getpid(void)
{
    /* printf("getpid()\n"); */
	return __syscall(SYS_getpid);
}
