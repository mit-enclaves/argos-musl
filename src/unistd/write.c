#include <unistd.h>
#include "syscall.h"
#include "tyche.h"

ssize_t write(int fd, const void *buf, size_t count)
{
    if (fd == TYCHE_CONNECTION_FD) {
        return tyche_write(fd, buf, count);
    }
    tyche_suicide(103);
    return syscall_cp(SYS_write, fd, buf, count);
}
