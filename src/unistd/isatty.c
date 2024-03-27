#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "syscall.h"
#include "tyche.h"

int isatty(int fd)
{
    return tyche_isatty(fd);
	struct winsize wsz;
	unsigned long r = syscall(SYS_ioctl, fd, TIOCGWINSZ, &wsz);
	if (r == 0) return 1;
	if (errno != EBADF) errno = ENOTTY;
	return 0;
}
