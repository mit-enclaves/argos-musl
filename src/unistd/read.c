#include <unistd.h>
#include "syscall.h"
#include "tyche.h"

ssize_t read(int fd, void *buf, size_t count)
{
    if (fd == TYCHE_CONNECTION_FD) {
        return tyche_read(fd, buf, count);
    }
    int* suicide = (int*) 0xdeadbabe;
    *suicide = 102;
    return syscall_cp(SYS_read, fd, buf, count);
}
