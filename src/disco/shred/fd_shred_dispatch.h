#ifndef HEADER_fd_src_disco_shred_fd_shred_dispatch_h
#define HEADER_fd_src_disco_shred_fd_shred_dispatch_h
#include "../../ballet/siphash13/fd_siphash13.h"

/* One independently random key per validator topology/workspace lifetime.
   All shred tiles join the SAME immutable object. Never use per-tile seeds. */
typedef struct { ulong k0, k1; } fd_shred_dispatch_key_t;
FD_STATIC_ASSERT( sizeof(fd_shred_dispatch_key_t)==16UL, dispatch_key_size );

/* Resolver owner: preserve co-location even across different
   signatures/roots for one (slot,FEC). Explicit little-endian serialization. */
FD_FN_PURE static inline ulong
fd_shred_dispatch_fec_owner( fd_shred_dispatch_key_t const * key,
                             ulong slot, uint fec, ulong tile_cnt ) {
  FD_TEST( tile_cnt );
  uchar msg[12];
  for( ulong i=0UL; i<8UL; i++ ) msg[i]     = (uchar)(slot>>(8UL*i));
  for( ulong i=0UL; i<4UL; i++ ) msg[8UL+i] = (uchar)(fec >>(8UL*i));
  return fd_siphash13_hash( msg, sizeof(msg), key->k0, key->k1 ) % tile_cnt;
}
#endif
