#ifndef HEADER_fd_src_util_fd_util_base_h
#error "Do not include this directly; use fd_util_base.h"
#endif

#ifndef FD_HW_MFENCE
#define FD_HW_MFENCE()    __sync_synchronize()
#define FD_HW_MFENCE_LD() __sync_synchronize()
#define FD_HW_MFENCE_ST() __sync_synchronize()
#endif

#ifndef FD_SPIN_PAUSE
#define FD_SPIN_PAUSE() ((void)0)
#endif

/* Portable fallback (slow).  Ticks at 1 ns / tick */
#ifndef fd_tickcount
#define fd_tickcount() fd_log_wallclock() /* TODO: fix ugly pre-log usage */
#endif

#if FD_HAS_ATOMIC && !defined(FD_ATOMIC_XCHG)
#define FD_ATOMIC_XCHG(p,v) __atomic_exchange_n( (p), (v), __ATOMIC_SEQ_CST )
#endif
