#include <sys/epoll.h>
#include <signal.h>
#include <errno.h>
#include "syscall.h"
#include "stdio.h"

int epoll_create(int size)
{
    printf("epoll_create()\n");
	return epoll_create1(0);
}

int epoll_create1(int flags)
{
	int r = __syscall(SYS_epoll_create1, flags);
    printf("epoll_create1()\n");
#ifdef SYS_epoll_create
	if (r==-ENOSYS && !flags) r = __syscall(SYS_epoll_create, 1);
#endif
	return __syscall_ret(r);
}

int epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev)
{
    printf("epoll_ctf(%d, %d, %d)\n", fd, op, fd2);
	return syscall(SYS_epoll_ctl, fd, op, fd2, ev);
}

int epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs)
{
	int r = __syscall_cp(SYS_epoll_pwait, fd, ev, cnt, to, sigs, _NSIG/8);
    printf("epoll_pwait(%d)\n", fd);
#ifdef SYS_epoll_wait
	if (r==-ENOSYS && !sigs) r = __syscall_cp(SYS_epoll_wait, fd, ev, cnt, to);
#endif
	return __syscall_ret(r);
}

int epoll_wait(int fd, struct epoll_event *ev, int cnt, int to)
{
    printf("epoll_wait(%d)\n", fd);
	return epoll_pwait(fd, ev, cnt, to, 0);
}
