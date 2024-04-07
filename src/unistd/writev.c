#include <sys/uio.h>
#include "syscall.h"
#include "tyche.h"

ssize_t writev(int fd, const struct iovec *iov, int count)
{
    if (fd == TYCHE_CONNECTION_FD) {
        return tyche_writev(fd, iov, count);
    }
	return syscall_cp(SYS_writev, fd, iov, count);
}
