#include <sys/socket.h>
#include "syscall.h"
#include "stdio.h"
#include "tyche.h"

int accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict len)
{
    printf("accept(%d)\n", fd);
    return tyche_accept(fd);
	return socketcall_cp(accept, fd, addr, len, 0, 0, 0);
}
