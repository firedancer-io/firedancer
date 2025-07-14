#ifndef HEADER_fd_src_util_futex_fd_futex_h
#define HEADER_fd_src_util_futex_fd_futex_h

#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>

/* fd_futex allows tiles to sleep when idle instead of busy-spinning.

   The system accomplishes this with futex-based signaling:
   1. Each mcache header contains a futex_flag field
   2. Producers update this flag after publishing messages
   3. Consumers sleep on these flags using futex_waitv
   4. Producers wake consumers using futex_wake

   The futex_flag contains the producer's sequence number and this allows
   consumers to detect if new work has arrived since they last checked. */

/* Futex syscall wrappers */

long syscall(long number, ...);

static inline long
fd_futex_wake(uint32_t *addr, int n) {
    return syscall(SYS_futex, addr, FUTEX_WAKE, n, NULL, NULL, 0);
}

static inline long
fd_futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes, struct timespec *timeout, int clockid) {
    return syscall(SYS_futex_waitv, waiters, nr_futexes, 0, timeout, clockid);
}

#endif /* HEADER_fd_src_util_futex_fd_futex_h */
