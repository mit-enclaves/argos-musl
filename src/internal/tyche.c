// Changes to accomodate running on top of Tyche
#include <fcntl.h>
#include <errno.h>
#include "unistd.h"
#include "stdio.h"
#include "tyche.h"
#include "stdlib.h"
#include "string.h"

enum tyche_test_state {
    TTS_INIT,
    TTS_START,
    TTS_DONE,
} tyche_test_state;

int connection_accepted = 0;
int connection_selected = 0;
enum tyche_test_state state = TTS_INIT;

void tyche_debug() {
    /* printf("Tyche Debug :)\n"); */
}

pid_t tyche_getpid() {
    return 1;
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
    return 0;
}

int tyche_select(int n, fd_set *restrict rfds, fd_set *restrict wfds) {
    printf("Tyche select\n");

    printf("Read set:\n");
    for (int i = 0; i < 32; i++) {
        if (FD_ISSET(i, rfds)) {
            printf("  %d\n", i);
        }
    }
    printf("Write set:\n");
    for (int i = 0; i < 32; i++) {
        if (FD_ISSET(i, wfds)) {
            printf("  %d\n", i);
        }
    }

    // Clear all bits
    FD_ZERO(rfds);
    FD_ZERO(wfds);

    if (!connection_selected) {
        // Set the bit for the Tyche socket
        FD_SET(TYCHE_SOCKET_FD, rfds);
        connection_selected = 1;
    } else {
        switch (state) {
            case TTS_INIT:
                FD_SET(TYCHE_CONNECTION_FD, rfds);
                state = TTS_START;
                break;
            default:
                printf("Done testing, blocking on select\n");
                while (1) {
                    exit(0);
                }
                break;
        }
    }

    printf("Returning from select\n");
    /* exit(0); */
    return 1;
}

#define REDIS_CMD_PING "PING\r\n"

ssize_t tyche_read(int fd, void *buff, size_t count) {
    printf("Tyche read: %d, count: %d\n", fd, count);
    switch (state) {
        case TTS_START:
            char *cmd = REDIS_CMD_PING;
            state = TTS_DONE;
            strcpy(buff, cmd);
            printf("  %s", cmd);
            return strlen(cmd);
        default:
            printf("Done reading\n");
            break;
    }
    return 0;
}

ssize_t tyche_write(int fd, const void *buf, size_t count) {
    printf("Tyche write:\n  %.*s", count, buf);
    return count;
}
