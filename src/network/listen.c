#include <sys/socket.h>
#include "syscall.h"
#include "stdio.h"
#include "tyche.h"

int listen(int fd, int backlog)
{
    printf("listen(%d)\n", fd);
    return tyche_listen(fd);
	return socketcall(listen, fd, backlog, 0, 0, 0, 0);
}
