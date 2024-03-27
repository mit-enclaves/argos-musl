#include <sys/socket.h>
#include "stdio.h"

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    printf("recv(%d)\n", fd);
	return recvfrom(fd, buf, len, flags, 0, 0);
}
