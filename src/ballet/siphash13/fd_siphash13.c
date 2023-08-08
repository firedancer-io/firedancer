#include "fd_siphash13.h"

#define FD_SIPHASH_ROUND(a,b,c,d)        \
  do {                                   \
    (a) += (b);                          \
    (b) = fd_ulong_rotate_left((b), 13); \
    (b) ^= (a);                          \
    (a) = fd_ulong_rotate_left((a), 32); \
    (c) += (d);                          \
    (d) = fd_ulong_rotate_left((d), 16); \
    (d) ^= (c);                          \
    (a) += (d);                          \
    (d) = fd_ulong_rotate_left((d), 21); \
    (d) ^= (a);                          \
    (c) += (b);                          \
    (b) = fd_ulong_rotate_left((b), 17); \
    (b) ^= (c);                          \
    (c) = fd_ulong_rotate_left((c), 32); \
  } while (0)

ulong
fd_siphash13_hash( void const * data,
                   ulong        data_sz,
                   ulong        k0,
                   ulong        k1 ) {

  /* Initialize */

  ulong v0 = 0x736f6d6570736575ULL;
  ulong v1 = 0x646f72616e646f6dULL;
  ulong v2 = 0x6c7967656e657261ULL;
  ulong v3 = 0x7465646279746573ULL;

  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  /* Hash blocks */

  ulong m;
  ulong const * in    = (ulong const *)data;
  ulong const * end   = in + data_sz/8UL;
  for( ; in!=end; in++ ) {
    m = *in;
    v3 ^= m;
    FD_SIPHASH_ROUND( v0, v1, v2, v3 );
    v0 ^= m;
  }

  /* Hash last block */

  int const     left = data_sz & 7;
  ulong         b    = ((ulong)data_sz) << 56;
  uchar const * rem  = (uchar const *)in;
  switch( left ) {
    case 7: b |= ((ulong)rem[6]) << 48; __attribute__((fallthrough));
    case 6: b |= ((ulong)rem[5]) << 40; __attribute__((fallthrough));
    case 5: b |= ((ulong)rem[4]) << 32; __attribute__((fallthrough));
    case 4: b |= ((ulong)rem[3]) << 24; __attribute__((fallthrough));
    case 3: b |= ((ulong)rem[2]) << 16; __attribute__((fallthrough));
    case 2: b |= ((ulong)rem[1]) <<  8; __attribute__((fallthrough));
    case 1: b |= ((ulong)rem[0]); break;
    case 0: break;
  }

  v3 ^= b;
  FD_SIPHASH_ROUND( v0, v1, v2, v3 );
  v0 ^= b;

  /* Finalize */

  v2 ^= 0xff;
  FD_SIPHASH_ROUND( v0, v1, v2, v3 );
  FD_SIPHASH_ROUND( v0, v1, v2, v3 );
  FD_SIPHASH_ROUND( v0, v1, v2, v3 );
  b = v0 ^ v1 ^ v2 ^ v3;

  return b;
}
