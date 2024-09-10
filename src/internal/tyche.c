// Changes to accomodate running on top of Tyche
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include "unistd.h"
#include "stdio.h"
#include "tyche.h"
#include "stdlib.h"
#include "string.h"
#include "syscall.h"
#include "tyche_rb.h"
#include "tyche_alloc.h"
#include <sys/ioctl.h>

RB_DECLARE_ALL(char);

#ifndef TYCHE_NO_SYSCALL
#define RB_SIZE 100
static char read_queue_buff[RB_SIZE];
static rb_char_t read_queue;
static int read_queue_is_init = 0;

#else

#define MSG_BUFFER_SIZE 1048

/// The seal enclave shared memory gets typecasted to this.
typedef struct seal_app_t {
  // Sending things to seal.
  rb_char_t to_seal;
  // Receiving messages from seal.
  rb_char_t from_seal;
  // Buffer for the to_seal.
  char to_buffer[MSG_BUFFER_SIZE];
  // Buffer for the from_seal.
  char from_buffer[MSG_BUFFER_SIZE];
} seal_app_t;

// This is all part of the shared state introduced by tychools.
// The untrusted code is responsible for initializing the channels.
static seal_app_t * app = (seal_app_t*) TYCHE_SHARED_ADDR;
static int read_queue_is_init = 1;
#endif

enum tyche_test_state {
    TTS_INIT,
    TTS_START,
    TTS_DONE,
} tyche_test_state;

int connection_accepted = 0;
int connection_selected = 0;
enum tyche_test_state state = TTS_INIT;

int most_recent_fd = 1234;
int fd_urandom = 0;

void tyche_debug(unsigned long long marker) {
    LOG("Tyche Debug:\n");
#ifndef TYCHE_NO_SYSCALL
    printf("Tyche Debug :)\n");
#else
  __asm__ __volatile__ (
      "movq %0, %%rdi\n\t"
      "movq $10, %%rax\n\t"
      "vmcall\n\t"
      :
      : "rm" (marker)
      : "rax", "rdi", "memory");
#endif
}

long tyche_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {

    //if(a1 != fd_urandom) {
    //    LOG("Syscall %lld with args %lld, %lld, %lld, %lld, %lld, %lld\n", n, a1, a2, a3, a4, a5, a6);
    //}
    switch (n) {
        // case SYS_getpid:
        //     return tyche_getpid();
        // case SYS_gettid:
        //     return tyche_gettid();
        // case SYS_ioctl:
        //     if (a2 == TIOCGWINSZ) {
        //         return tyche_isatty(a1);
        //     }
        //     else {
        //         tyche_suicide(0);
        //         break;
        //     }
        // case SYS_getcwd:
        //     return (long) tyche_getcwd((char *) a1, a2);
        // case SYS_fcntl:
        //     return tyche_fcntl(a1, a2);
        // case SYS_open:
        //     return tyche_open((const char *) a1, a2, a3, a4, a5, a6);
        // case SYS_close:
        //     return tyche_close(a1);
        // case SYS_bind:
        //     return tyche_bind(a1);
        // case SYS_listen:
        //     return tyche_listen(a1);
        // case SYS_read:
        //     return tyche_read(a1, (void *) a2, a3);
        // case SYS_setsockopt:
        //     return tyche_setsockopt(a1);
        // case SYS_socket:
        //     return tyche_socket();
        // case SYS_select:
        //     return tyche_select(a1, (void *) a2, (void *) a3);
        // case SYS_gettimeofday:
        //     return tyche_gettimeofday((void *) a1, (void *) a2);
        // case SYS_write:
        //     return tyche_write(a1, (void *) a2, a3);
        // case SYS_writev:
        //     return tyche_writev(a1, (void *) a2, a3);
        case SYS_mmap:
            return (long) tyche_mmap((void *) a1, a2, a3, a4, a5, a6);
        case SYS_munmap:
            return tyche_munmap((void *) a1, a2);
        // case SYS_brk:
        //    return tyche_brk((void *) a1);
        // case SYS_rt_sigprocmask:
        //     return tyche_rt_sigprocmask(a1, (void *) a2, (void *) a3, a4);
        case SYS_exit_group:
        case SYS_exit:
        case SYS_tkill:
            #if ALLOC_DEBUG == 1
            print_allocation_info();
            print_mempool_state();
            #endif
            //tyche_exit(a1);
            //break;
        default:
            unsigned long ret;
            register long r10 __asm__("r10") = a4;
            register long r8 __asm__("r8") = a5;
            register long r9 __asm__("r9") = a6;
            __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
            					  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
            return ret;
    }
    return 0;
}

// Get randomness from Intel's RNG
// See https://stackoverflow.com/questions/11407103/how-i-can-get-the-random-number-from-intels-processor-with-assembler
int tyche_random(char* buff, size_t bsize)
{
    size_t idx = 0, rem = bsize;
    size_t safety = bsize / sizeof(unsigned int) + 4; // Prevent infinite loop if the instruction fails more than 4 times

    unsigned int val;
    while (rem > 0 && safety > 0)
    {
        char rc;
        __asm__ volatile(
                "rdrand %0 ; setc %1"
                : "=r" (val), "=qm" (rc)
        );

        // 1 = success, 0 = underflow
        if (rc)
        {
            size_t cnt = (rem < sizeof(val) ? rem : sizeof(val)); // Only copy what is required
            memcpy(buff + idx, &val, cnt);

            rem -= cnt;
            idx += cnt;
        }
        else
        {
            safety--;
        }
    }

    // Wipe temp on exit
    *((volatile unsigned int*)&val) = 0;

    //LOG("Randomness: ");
    //LOG_BYTES(buff, bsize);
    //LOG("\n");

    // 0 = success; non-0 = failure (possibly partial failure).
    return (int)(bsize - rem);
}


pid_t tyche_getpid() {
    return 1;
}

pid_t tyche_gettid() {
    return 1;
}

int tyche_isatty(int fd) {
    return 1;
}

char *tyche_getcwd(char *buf, size_t size) {
    char *pwd = "/tmp/tyche-seal";
    strncpy(buf, pwd, size);
    return strdup(pwd);
}

int tyche_gettimeofday(struct timeval *restrict tv, void *restrict tz) {
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

int tyche_socket() {
    // We only support a single socket for now
    return TYCHE_SOCKET_FD;
}

int tyche_setsockopt(int fd) {
    printf("setsockopt: %d\n", fd);
    // Ignore all options
    return 0;
}

int tyche_bind(int fd) {
    // Just say it succeeded
    return 0;
}

int tyche_listen(int fd) {
    // Just say it succeeded
    return 0;
}

int tyche_accept(int fd) {
    // Initialize read queue so that the socket has some content

#ifndef TYCHE_NO_SYSCALL
    if (!read_queue_is_init) {
        memset(read_queue_buff, 0, sizeof(char) * RB_SIZE);
        rb_char_init(&read_queue, RB_SIZE, read_queue_buff);
        read_queue_is_init = 1;

        // Put initial commands
        char *cmds = "PING\r\nSET A 666\r\nCOMMAND\r\nGET A\r\n";
        printf("Commands:\n%s", cmds);
        rb_char_write_n(&read_queue, strlen(cmds), cmds);
    }
#endif

    if (!connection_accepted) {
        printf("Accepting connection\n");
        connection_accepted = 1;
        return TYCHE_CONNECTION_FD;
    } else {
        errno = EAGAIN;
        return -1;
    }
}

int tyche_fcntl(int fd, int flags) {
    if (fd == TYCHE_CONNECTION_FD) {
        if (flags == F_GETFL) {
            printf("  F_GETFL\n");
            return  0x2; // Access rights for the connection
        } else if (flags == F_SETFL) {
            printf("  F_SETFL\n");
            return 0;
        } else if (flags == F_GETFD) {
            printf("  F_GETFD\n");
            return 0;
        } else if (flags == F_SETFD) {
            printf("  F_SETFD\n");
            return 0;
        }
    }
    else {
        tyche_suicide(0);
    }
    return 0;
}

int tyche_select(int n, fd_set *restrict rfds, fd_set *restrict wfds) {
    //printf("Tyche select\n");

    //printf("Read set:\n");
    for (int i = 0; i < 32; i++) {
        if (FD_ISSET(i, rfds)) {
            //printf("  %d\n", i);
        }
    }
    //printf("Write set:\n");
    for (int i = 0; i < 32; i++) {
        if (FD_ISSET(i, wfds)) {
            //printf("  %d\n", i);
        }
    }

    // Clear all bits
    FD_ZERO(rfds);
    FD_ZERO(wfds);

    if (!connection_selected) {
        // Set the bit for the Tyche socket
        FD_SET(TYCHE_SOCKET_FD, rfds);
        connection_selected = 1;
        //printf("Connection ready to accept\n");
        return 1;
    } else {
#ifndef TYCHE_NO_SYSCALL
        unsigned long long count = 0;
        while(rb_char_is_empty(&read_queue)) {
            count += 1;
            if (count > 1000000) {
                printf("No more messages, exiting\n");
                while (1) {
                    exit(0);
                }
            }
        }
#else
        while (rb_char_is_empty(&(app->to_seal))) {}
#endif
        // We got some messages on the channel!
        FD_SET(TYCHE_CONNECTION_FD, rfds);
        //printf("Channel ready to be read\n");
        return 1;
        /* switch (state) { */
        /*     case TTS_INIT: */
        /*         FD_SET(TYCHE_CONNECTION_FD, rfds); */
        /*         state = TTS_START; */
        /*         break; */
        /*     default: */
        /*         printf("Done testing, blocking on select\n"); */
        /*         while (1) { */
        /*             exit(0); */
        /*         } */
        /*         break; */
        /* } */
    }
}

int tyche_open(const char *filename, int flags, ...) {
    int fd = most_recent_fd++;
    if (strcmp(filename, "/dev/urandom") == 0) {
       fd_urandom = fd;
    }
    return fd;
}

int tyche_close(int fd) {
    return 0;
}

size_t tyche_read(int fd, void *buff, size_t count) {
    if (fd == fd_urandom) {
        int ret = tyche_random(buff, count);
        return ret;
    }
#ifndef TYCHE_NO_SYSCALL
  printf("Tyche read: %d, count: %d\n", fd, count);
  int ret = rb_char_read_n(&read_queue, (int) count, (char *)buff);
#else
    int ret = rb_char_read_alias_n(&(app->to_seal), app->to_buffer, (int) count, (char *)buff);
#endif
    if (ret == FAILURE) {
      tyche_suicide(101);
      errno = EAGAIN;
      return 0;
    }
    return ret;
}

size_t tyche_write(int fd, const void *buf, size_t count) {
#ifndef TYCHE_NO_SYSCALL
    printf("Tyche write:\n  %.*s", count, buf);
#else
    int written = 0;
    char *source = (char *) buf;
    while (written < count) {
      int res = rb_char_write_alias_n(&(app->from_seal), app->from_buffer, count - written, &source[written]);
      if (res == FAILURE) {
        //TODO: figure something out.
        tyche_suicide(100);
        return 0;
      }
      written += res;
    }
#endif
    return count;
}

ssize_t tyche_writev(int fd, const struct iovec *iov, int count) {
    ssize_t n = 0;
#ifndef TYCHE_NO_SYSCALL
    printf("Tyche writev: count %d\n ", count);
#endif
    for (int i = 0; i < count; i++) {
        n += tyche_write(fd, iov[i].iov_base, iov[i].iov_len);
    }
    return n;
}

int tyche_rt_sigprocmask(int how, const uint64_t *set, uint64_t *oldset, size_t sigsetsize) {
    // TODO: Implement if needed
    return 0;
}

void tyche_suicide(unsigned int v) {
  LOG("Entered tyche_suicide with value %d\n", v);
  int* suicide = (int *) 0xdeadbabe;
  tyche_debug(v);
  *suicide = v;
}


void tyche_exit(int ec) {
#ifndef TYCHE_NO_SYSCALL
    printf("Tyche Debug :)\n");
#else
    LOG("Tyche Exit\n");
    __asm__ __volatile__ (
      "movq %0, %%rdi\n\t"
      "movq $9, %%rax\n\t"
      "vmcall\n\t"
      :
      : "rm" (ec)
      : "rax", "rdi", "memory");
#endif
tyche_suicide(0xdead);
}

// ——————————————————————————— Memory Management ———————————————————————————— //


void *tyche_mmap(void *start, size_t len, int prot, int flags, int fd, off_t off) {
    
    // We just ignore PROT_NONE as it is used only for guard pages
    if (prot == PROT_NONE) {
        return start;
    }

    // Print a warning if we are mapping a file, this is not supported!
    if (fd != -1) {
      tyche_suicide(0xB00B1);
      return NULL;
    }
    
    void* res = alloc_segment(len);
    
    if(flags & MAP_ANONYMOUS) {
        memset(res, 0, len);
    }

    //LOG("Called mmap for size %llx and returned addr 0x%llx\n", len, res);
    return res;
}

int tyche_munmap(void *start, size_t len) {
    int ret = free_segment(start, len);
    //LOG("munmap for size %llx at addr 0x%llx\n", len, start);
    return ret;
}

#define BRK_NB_PAGES 20
static char brk_pool[BRK_NB_PAGES * PAGE_SIZE];
static char *brk_cursor;
static int brk_is_init = 0;

size_t tyche_brk(void *end) {
    // Initialize if needed
    if (!brk_is_init) {
        brk_cursor = brk_pool;
        brk_is_init = 1;
    }

    if (end == NULL) {
        return (size_t)brk_cursor;
    }

    if ((size_t)end > (size_t)brk_pool + BRK_NB_PAGES * PAGE_SIZE || (size_t)end < (size_t)brk_pool) {
        LOG("Invalid brk!!!\n");
        return -ENOMEM;
    } else {
        brk_cursor = end;
        return (size_t)end;
    }
}