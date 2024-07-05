#include "stdio_impl.h"
#include "tyche.h"

#undef stdout

size_t _tyche_stdout_write(FILE *f, const unsigned char *buf, size_t len) {
    tyche_write(f->fd, buf, len);
    return len;
}

static unsigned char buf[BUFSIZ+UNGET];
hidden FILE __stdout_FILE = {
	.buf = buf+UNGET,
	.buf_size = sizeof buf-UNGET,
	.fd = 1,
	.flags = F_PERM | F_NORD,
	.lbf = '\n',
#ifdef TYCHE_NO_SYSCALL
    .write = _tyche_stdout_write,
#else
	.write = __stdout_write,
#endif
	.seek = __stdio_seek,
	.close = __stdio_close,
	.lock = -1,
};
FILE *const stdout = &__stdout_FILE;
FILE *volatile __stdout_used = &__stdout_FILE;
