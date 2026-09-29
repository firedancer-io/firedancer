#define _GNU_SOURCE
#include "fd_tile.h"

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

/* glibc>=2.35 (and RHEL 9's 2.34 backport) registers rseq on every
   thread and exports the area through <sys/rseq.h>.  Older glibc and
   musl register nothing, so there is nothing to unregister. */
#if defined(__has_include)
#if __has_include(<sys/rseq.h>)
#include <sys/rseq.h>
#define FD_TILE_HAS_GLIBC_RSEQ 1
#endif
#endif
#ifndef FD_TILE_HAS_GLIBC_RSEQ
#define FD_TILE_HAS_GLIBC_RSEQ 0
#endif

int
fd_tile_rseq_unregister( void ) {
#if FD_HAS_X86 && FD_TILE_HAS_GLIBC_RSEQ
  if( FD_UNLIKELY( !__rseq_size ) ) return 0; /* glibc did not register rseq */

  ulong tp; __asm__( "mov %%fs:0, %0" : "=r"(tp) ); /* x86-64 thread pointer */
  struct rseq * rs = (struct rseq *)( tp + (ulong)__rseq_offset );
  if( FD_UNLIKELY( (int)FD_VOLATILE_CONST( rs->cpu_id )<0 ) ) return 0; /* unregistered or registration failed */

  /* __rseq_size is the used feature size (20 on this ABI), glibc
     registers it rounded up to the 32 byte struct rseq alignment. */
  uint len = fd_uint_align_up( fd_uint_max( __rseq_size, 32U ), 32U );
  if( FD_UNLIKELY( syscall( SYS_rseq, rs, len, RSEQ_FLAG_UNREGISTER, 0x53053053U /* x86 RSEQ_SIG */ ) ) ) {
    FD_LOG_WARNING(( "rseq(RSEQ_FLAG_UNREGISTER) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return 0;
  }
  return 1;
#else
  return 0; /* no glibc rseq area, or not x86-64 */
#endif
}
