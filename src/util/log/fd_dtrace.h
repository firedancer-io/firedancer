#ifndef HEADER_fd_src_util_log_fd_dtrace_h
#define HEADER_fd_src_util_log_fd_dtrace_h

/* fd_dtrace.h provides wrappers for software-defined trace points. */

#ifdef __has_include
#if __has_include(<sys/sdt.h>) && defined(__linux__)
#define FD_HAS_SDT 1
#endif
#endif

#ifndef FD_HAS_SDT
#define FD_HAS_SDT 0
#endif

#if FD_HAS_SDT

#if defined(__clang__) && (__clang_major__ == 19)
/* Work around an incompatibility between Clang 19 and SystemTap SDT */
#pragma GCC diagnostic ignored "-Wc23-extensions"
#endif

#include <sys/sdt.h>

#define FD_DTRACE_PROBE(name)                  DTRACE_PROBE(Firedancer,name)
#define FD_DTRACE_PROBE_1(name,a1)             DTRACE_PROBE1(Firedancer,name,a1)
#define FD_DTRACE_PROBE_2(name,a1,a2)          DTRACE_PROBE2(Firedancer,name,a1,a2)
#define FD_DTRACE_PROBE_3(name,a1,a2,a3)       DTRACE_PROBE3(Firedancer,name,a1,a2,a3)
#define FD_DTRACE_PROBE_4(name,a1,a2,a3,a4)    DTRACE_PROBE4(Firedancer,name,a1,a2,a3,a4)
#define FD_DTRACE_PROBE_5(name,a1,a2,a3,a4,a5) DTRACE_PROBE5(Firedancer,name,a1,a2,a3,a4,a5)

#else

#define FD_DTRACE_PROBE(name)
#define FD_DTRACE_PROBE_1(name,a1)             (void)((a1));
#define FD_DTRACE_PROBE_2(name,a1,a2)          (void)((a1)); (void)((a2));
#define FD_DTRACE_PROBE_3(name,a1,a2,a3)       (void)((a1)); (void)((a2)); (void)((a3));
#define FD_DTRACE_PROBE_4(name,a1,a2,a3,a4)    (void)((a1)); (void)((a2)); (void)((a3)); (void)((a4));
#define FD_DTRACE_PROBE_5(name,a1,a2,a3,a4,a5) (void)((a1)); (void)((a2)); (void)((a3)); (void)((a4)); (void)((a5));

#endif /* FD_HAS_SDT */

#endif /* HEADER_fd_src_util_log_fd_dtrace_h */
