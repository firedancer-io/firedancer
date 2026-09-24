#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_idiv_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_idiv_h

/* fd_transpile_idiv.h provides helpers for strength reducing integer
   division by a constant. */

#include "fd_transpile.h"

FD_PROTOTYPES_BEGIN

/* fd_transpile_udiv{32,64}_magic derive a round-up multiplier for
   unsigned W-bit division (W=32,64) by a constant d that is neither
   zero nor a power of two.  Returns m = ceil(2^k/d) and writes k to *k,
   where k is the smallest shift in [W,W+ceil(log2 d)] such that
   m*d <= 2^k + 2^(k-W).  Then n/d == (n*m)>>k for all W-bit n
   (Granlund-Montgomery).  m can be W+1 bits wide, so the caller must
   handle the 2^W bit separately. */

static inline ulong
fd_transpile_udiv32_magic( uint  d,
                           int * k ) {
  int l = 0;
  while( (1UL<<l)<(ulong)d ) l++;
  for( int s=32; s<=32+l; s++ ) {
    uint128 p = (uint128)1<<s;
    uint128 m = (p+(uint128)d-1U)/(uint128)d;
    if( m*(uint128)d<=p+(p>>32) ) {
      *k = s;
      return (ulong)m;
    }
  }
  FD_LOG_CRIT(( "no udiv32 magic for %u", d )); /* unreachable */
}

static inline uint128
fd_transpile_udiv64_magic( ulong d,
                           int * k ) {
  int l = 0;
  while( l<63 && (1UL<<l)<d ) l++;
  for( int s=64; s<=64+l; s++ ) {
    uint128 p = (uint128)1<<s;
    uint128 m = (p+(uint128)d-1U)/(uint128)d;
    if( m*(uint128)d<=p+(p>>64) ) {
      *k = s;
      return m;
    }
  }
  FD_LOG_CRIT(( "no udiv64 magic for %lu", d )); /* unreachable */
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_idiv_h */
