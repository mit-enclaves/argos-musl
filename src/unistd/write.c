#include <unistd.h>
#include "syscall.h"
#include "tyche.h"

ssize_t write(int fd, const void *buf, size_t count)
{
    return syscall_cp(SYS_write, fd, buf, count);
}
