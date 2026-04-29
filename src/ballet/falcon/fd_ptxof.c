#include "fd_ptxof.h"
#include "../keccak256/fd_shake256.h"
#include "../keccak256/fd_keccak256_private.h"
#include "fd_keccak8x.h"

// #if FD_HAS_S2NBIGNUM
// static inline void
// fd_keccak256_core_4( ulong state[4][25] ) {
//   sha3_keccak4_f1600( (uint64_t *)state, (const uint64_t *)fd_keccak256_rc );
// }
// #else
// static inline void
// fd_keccak256_core_4( ulong state[4][25] ) {
//   for( ulong i=0UL; i<4; i++ ) {
//     fd_keccak256_core( state[i] );
//   }
// }
// #endif

void
fd_ptxof_init( fd_ptxof_t * pt ) {
  pt->offset = 0UL;
  pt->idx    = 0UL;
  fd_memset( pt->bytes[0], 0, 200UL );
  /* Leave the last 3 states undefined, they will be set in fini(). */
}

void
fd_ptxof_absorb( fd_ptxof_t  * pt,
                 uchar const * data,
                 ulong         len ) {
  ulong off = pt->offset;
  for( ulong i=0UL; i<len; i++ ) {
    pt->bytes[0][off] ^= data[i];
    off++;
    if( FD_UNLIKELY( FD_SHAKE256_RATE==off ) ) {
      fd_keccak256_core( pt->state[0] );
      off = 0UL;
    }
  }
  pt->offset = off;
}

void
fd_ptxof_fini( fd_ptxof_t * pt ) {
  pt->bytes[0][ pt->offset ] ^= (uchar)0x1F;
  pt->bytes[0][ FD_SHAKE256_RATE-1 ] ^= (uchar)0x80;
  fd_keccak256_core( pt->state[0] );
  pt->offset = 0UL;

  /* Broadcast the absorbed state across 4 lanes,
     each made unique with a counter. */
  for( ulong i=1UL; i<FD_PTXOF_PARALLEL; i++ ) {
    fd_memcpy( pt->bytes[i], pt->bytes[0], 200UL );
    pt->bytes[i][0] += (uchar)i;
  }
}

void
fd_ptxof_squeeze( fd_ptxof_t * pt,
                  uchar      * out,
                  ulong        len ) {
  ulong off = pt->offset;
  ulong idx = pt->idx;
  for( ulong i=0UL; i<len; i++ ) {
    if( FD_UNLIKELY( FD_SHAKE256_RATE==off ) ) {
      if( FD_UNLIKELY( FD_PTXOF_PARALLEL-1==pt->idx ) ) {
        fd_keccak256_core_8( pt->state );
        idx = 0UL;
      }
      off = 0UL;
      idx++;
    }
    out[i] = pt->bytes[idx][off];
    off++;
  }
  pt->offset = off;
  pt->idx    = idx;
}
