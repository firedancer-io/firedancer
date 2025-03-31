#ifndef HEADER_fd_src_waltz_h2_fd_hpack_private_h
#define HEADER_fd_src_waltz_h2_fd_hpack_private_h

#include "fd_hpack.h"

#if FD_HAS_X86
#include <immintrin.h>
#endif

/* Simple HPACK static table.
   FIXME could be made faster/smaller */

struct fd_hpack_static_entry {
  char const * entry;
  uchar        name_len;
  uchar        value_len;
};

typedef struct fd_hpack_static_entry fd_hpack_static_entry_t;

FD_PROTOTYPES_BEGIN

extern fd_hpack_static_entry_t const
fd_hpack_static_table[ 62 ];

/* fd_hpack_rd_varint reads a varint with up to 8 bytes encoded length
   (not including prefix).  addend is (2^n)-1 where n is the varint
   prefix bit count.  prefix is the actual value of the varint prefix.
   Returns a value in [0,2^56) on success.  Returns ULONG_MAX on decode
   failure. */

static inline ulong
fd_hpack_rd_varint( fd_hpack_rd_t * rd,
                    uint            prefix,
                    uint            addend ) {
  prefix &= addend;
  /* FIXME does not detect overflow */

  /* Length is 0 */
  if( prefix<addend ) return prefix;

  /* Read encoded word */
  ulong enc = 0UL;
  if( FD_LIKELY( rd->src+8 <= rd->src_end ) ) {
    /* happy path: speculatively read oob */
    enc = fd_ulong_load_8( rd->src );
  } else {
    /* slow path: carefully memcpy, handle potentially corrupt src_end */
    ulong sz = fd_ulong_min( (ulong)rd->src_end - (ulong)rd->src, 8UL );
    if( FD_UNLIKELY( !sz ) ) return ULONG_MAX; /* eof */
    fd_memcpy( &enc, rd->src, sz );
  }

  /* sz_run is a bit pattern indicating:

     length 1 => least-significant one bit is at index  7
     length 2 =>                - " -                  15
     ...
     length n =>                - " -             (8*n)-1 */
  ulong sz_run  = ~( enc | 0x7f7f7f7f7f7f7f7fUL );
  if( FD_UNLIKELY( sz_run==0 ) ) return ULONG_MAX; /* unterminated varint */
  int   sz_bits = fd_ulong_find_lsb( sz_run )+1;
  ulong sz      = (ulong)sz_bits>>3;

  /* Mask off garbage bits */
  enc &= fd_ulong_shift_left( 1UL, sz_bits )-1UL;

  /* Remove varint length bits */
#if FD_HAS_X86 && defined(__BMI2__)
  ulong result = _pext_u64( enc, 0x7f7f7f7f7f7f7f7fUL );
#else
  ulong result =
    ( ( enc&0x000000000000007fUL )>>0 ) |
    ( ( enc&0x0000000000007f00UL )>>1 ) |
    ( ( enc&0x00000000007f0000UL )>>2 ) |
    ( ( enc&0x000000007f000000UL )>>3 ) |
    ( ( enc&0x0000007f00000000UL )>>4 ) |
    ( ( enc&0x00007f0000000000UL )>>5 ) |
    ( ( enc&0x007f000000000000UL )>>6 ) |
    ( ( enc&0x7f00000000000000UL )>>7 );
#endif

  uchar const * src_end = rd->src+sz;
  if( FD_UNLIKELY( src_end>rd->src_end ) ) return ULONG_MAX; /* eof */
  rd->src = src_end;
  return result+addend;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_hpack_private_h */
