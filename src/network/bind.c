#include <sys/socket.h>
#include "syscall.h"
#include "tyche.h"
#include "stdio.h"

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    printf("bind(%d)\n", fd);
    return tyche_bind(fd);
	return socketcall(bind, fd, addr, len, 0, 0, 0);
}
