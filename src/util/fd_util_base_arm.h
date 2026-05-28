#ifndef HEADER_fd_src_util_fd_util_base_h
#error "Do not include this directly; use fd_util_base.h"
#endif

/* FD_HAS_ARM:  If the build target supports armv8-a specific features
   and can benefit from aarch64 specific optimizations, define
   FD_HAS_ARM. */

#ifndef FD_HAS_ARM
#define FD_HAS_ARM 0
#endif

#if FD_HAS_ARM

#define FD_HW_MFENCE()    __asm__ __volatile__( "dmb ish" ::: "memory" )
#define FD_HW_MFENCE_LD() __asm__ __volatile__( "dmb ishld" ::: "memory" )
#define FD_HW_MFENCE_ST() __asm__ __volatile__( "dmb ishst" ::: "memory" )

#define FD_SPIN_PAUSE() __asm__ __volatile__( "yield" ::: "memory" )

/* fd_tickcount (ARM): https://developer.arm.com/documentation/ddi0601/2021-12/AArch64-Registers/CNTVCT-EL0--Counter-timer-Virtual-Count-register
   Approx 24 MHz on Apple M1. */

static inline long
fd_tickcount( void ) {
  /* consider using 'isb' */
  ulong value;
  __asm__ __volatile__ (
    "isb\n"
    "mrs %0, cntvct_el0\n"
    "nop"
    : "=r" (value) );
  return (long)value;
}

/* fd_arm_stp16 stores two ulongs to a 16-byte memory location.
   If LSE2 and p is aligned, is single-copy atomic. */

static inline void
fd_arm_stp16( ulong * p,
              ulong   a,
              ulong   b ) {
  __asm__(
      "stp %x[a], %x[b], [%[p]]"
      :
      : [a] "r"(a), [b] "r"(b), [p] "r"(p)
      : "memory"
  );
}

/* fd_arm_ldp16 loads two ulongs from a 16-byte memory location.
   If LSE2 and p is aligned, is single-copy atomic. */

#define fd_arm_ldp16(p_,a_,b_)     \
  __asm__(                         \
      "ldp %x[a], %x[b], [%[p]]"   \
      : [a] "=r"(a_), [b] "=r"(b_) \
      : [p] "r"(p_)                \
      : "memory"                   \
  )

/* fd_arm_ldp16_acq_pc is like fd_arm_ldp16, but with Load-AcquirePC
   semantics.  Requires RCPC3. */

#define fd_arm_ldp16_acq_pc(p_,a_,b_) \
  __asm__(                            \
      "ldiapp %x[a], %x[b], [%[p]]"   \
      : [a] "=r"(a_), [b] "=r"(b_)    \
      : [p] "r"(p_)                   \
      : "memory"                      \
  )

#endif
