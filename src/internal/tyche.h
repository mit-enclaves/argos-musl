// Interface for Tyche specific functions

#ifndef _TYCHE_H
#define _TYCHE_H 1

#include "sys/select.h"
#include "sys/uio.h"
#include "unistd.h"
#include <stdint.h>
#include <stdarg.h>

// Comment/uncomment to enable or disable syscalls
#define TYCHE_NO_SYSCALL

#define TYCHE_SOCKET_FD 14
#define TYCHE_CONNECTION_FD 15
#define TYCHE_SHARED_ADDR 0x300000

void tyche_debug(unsigned long long marker);
int tyche_log(const char *format, ...);
void tyche_log_char_buffer(char* buff, int size);

#ifndef TYCHE_NO_SYSCALL
#include <stdio.h>
#define LOG printf
#else
#define LOG tyche_log
#endif
#define LOG_BYTES tyche_log_char_buffer

int tyche_socket();
int tyche_setsockopt(int fd);
int tyche_bind(int fd);
int tyche_listen(int fd);
int tyche_accept(int fd);
int tyche_fcntl(int fd, int flags);
int tyche_select(int n, fd_set* restrict rfds, fd_set* restrict wfds);
int tyche_open(const char *filename, int flags, ...);
int tyche_close(int fd);
size_t tyche_read(int fd, void* buff, size_t count);
size_t tyche_write(int fd, const void* buf, size_t count);
int tyche_gettimeofday(struct timeval* restrict tv, void* restrict tz);
pid_t tyche_getpid(void);
pid_t tyche_gettid(void);
char* tyche_getcwd(char* buf, size_t size);
int tyche_isatty(int fd);
void* tyche_mmap(void* start, size_t len, int prot, int flags, int fd, off_t off);
int tyche_munmap(void* start, size_t len);
size_t tyche_brk(void* end);
ssize_t tyche_writev(int fd, const struct iovec* iov, int count);
int tyche_rt_sigprocmask(int how, const uint64_t *set, uint64_t *oldset, size_t sigsetsize);
int tyche_futex(int *uaddr, int futex_op, int val, void *timeout, int *uaddr2, int val3);
void tyche_suicide(unsigned int v);
void tyche_exit(int ec);
long tyche_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6);
#endif
