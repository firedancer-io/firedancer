#ifndef HEADER_fd_src_util_futex_fd_futex_h
#define HEADER_fd_src_util_futex_fd_futex_h

#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>

/* Futex syscall wrappers */

long syscall(long number, ...);

static inline long 
fd_futex_wait(const uint32_t *addr, uint32_t val) {
    return syscall(SYS_futex, addr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static inline long 
fd_futex_wake(uint32_t *addr, int n) {
    return syscall(SYS_futex, addr, FUTEX_WAKE, n, NULL, NULL, 0);
}

static inline long 
fd_futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes, struct timespec *timeout, int clockid) {
    return syscall(SYS_futex_waitv, waiters, nr_futexes, 0, timeout, clockid);
}

#endif /* HEADER_fd_src_util_futex_fd_futex_h */ 
