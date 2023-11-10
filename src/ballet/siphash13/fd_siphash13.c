#include "fd_siphash13.h"

/* This code is a modified version of https://github.com/antirez/siphash
   For further license info see NOTICE in the root of this repo.

   Copyright (c) 2012-2016 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
   Copyright (c) 2017 Salvatore Sanfilippo <antirez@gmail.com>
   Modified 2023 by Firedancer Contributors */

static const ulong __attribute__((aligned(64UL)))
fd_siphash13_initial[4] = {
  0x736f6d6570736575UL,
  0x646f72616e646f6dUL,
  0x6c7967656e657261UL,
  0x7465646279746573UL,
};

fd_siphash13_t *
fd_siphash13_init( fd_siphash13_t * sip,
                   ulong            k0,
                   ulong            k1 ) {

  memset( sip, 0, sizeof(fd_siphash13_t) );

  ulong * v = sip->v;

  v[ 0 ] = fd_siphash13_initial[ 0 ];
  v[ 1 ] = fd_siphash13_initial[ 1 ];
  v[ 2 ] = fd_siphash13_initial[ 2 ];
  v[ 3 ] = fd_siphash13_initial[ 3 ];
  v[ 3 ] ^= k1;
  v[ 2 ] ^= k0;
  v[ 1 ] ^= k1;
  v[ 0 ] ^= k0;

  return sip;
}

static void
fd_siphash1N_core( ulong         v[ static 4 ],
                   uchar const * buf,
                   ulong         n ) {
  ulong m;
  for( ulong i=0UL; i<n; i++ ) {
    m = ((ulong const *)buf)[ i ];
    v[ 3 ] ^= m;
    FD_SIPHASH_ROUND( v );
    v[ 0 ] ^= m;
  }
}

fd_siphash13_t *
fd_siphash13_append( fd_siphash13_t * sip,
                     uchar const *    data,
                     ulong            sz ) {

  ulong * v        = sip->v;
  uchar * buf      = sip->buf;
  ulong   buf_used = sip->n & 7UL;

  sip->n += sz;

  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = 8UL - buf_used;
    if( FD_UNLIKELY( sz < buf_rem ) ) {
      fd_memcpy( buf + buf_used, data, sz );
      return sip;
    }

    /* Otherwise, buffer enough leading bytes of data complete the
       block, update the hash and then continue processing any remaining
       bytes of data. */

    fd_memcpy( buf + buf_used, data, buf_rem );
    data += buf_rem;
    sz   -= buf_rem;

    fd_siphash1N_core( v, buf, 1UL );
  }

  /* Append the bulk of the data */

  ulong block_cnt = sz >> 3;
  if( FD_LIKELY( block_cnt ) ) fd_siphash1N_core( v, data, block_cnt );

  /* Buffer any leftover bytes */

  buf_used = sz & 7UL;
  if( FD_UNLIKELY( buf_used ) )
    fd_memcpy( buf, data + (sz - buf_used), buf_used );

  return sip;
}

fd_siphash13_t *
fd_siphash13_append_fast( fd_siphash13_t * sip,
                          uchar const *    data,
                          ulong            sz ) {
  /* TODO debug assertions */
  sip->n += sz;
  fd_siphash1N_core( sip->v, data, sz >> 3 );
  return sip;
}

ulong
fd_siphash13_fini( fd_siphash13_t * sip ) {

  /* Unpack inputs */

  ulong * v        = sip->v;
  uchar * buf      = sip->buf;
  ulong   n        = sip->n;
  ulong   buf_used = sip->n & 7UL;

  /* Hash last block */

  ulong b = n<<56UL;
  switch( buf_used ) {
    case 7: b |= ((ulong)buf[6]) << 48; __attribute__((fallthrough));
    case 6: b |= ((ulong)buf[5]) << 40; __attribute__((fallthrough));
    case 5: b |= ((ulong)buf[4]) << 32; __attribute__((fallthrough));
    case 4: b |= ((ulong)buf[3]) << 24; __attribute__((fallthrough));
    case 3: b |= ((ulong)buf[2]) << 16; __attribute__((fallthrough));
    case 2: b |= ((ulong)buf[1]) <<  8; __attribute__((fallthrough));
    case 1: b |= ((ulong)buf[0]); break;
    case 0: break;
  }
  fd_siphash1N_core( v, (uchar const *)&b, 1UL );

  /* Finalize */

  v[ 2 ] ^= 0xff;
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  b = v[ 0 ] ^ v[ 1 ] ^ v[ 2 ] ^ v[ 3 ];
  return b;
}

FD_FN_PURE ulong
fd_siphash13_hash( void const * data,
                   ulong        data_sz,
                   ulong        k0,
                   ulong        k1 ) {

  /* Initialize */

  ulong v[ 4 ];
  memcpy( v, fd_siphash13_initial, 32UL );

  v[ 3 ] ^= k1;
  v[ 2 ] ^= k0;
  v[ 1 ] ^= k1;
  v[ 0 ] ^= k0;

  /* Hash blocks */

  ulong m;
  ulong const * in    = (ulong const *)data;
  ulong const * end   = in + data_sz/8UL;
  for( ; in!=end; in++ ) {
    m = *in;
    v[ 3 ] ^= m;
    FD_SIPHASH_ROUND( v );
    v[ 0 ] ^= m;
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

  v[ 3 ] ^= b;
  FD_SIPHASH_ROUND( v );
  v[ 0 ] ^= b;

  /* Finalize */

  v[ 2 ] ^= 0xff;
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  FD_SIPHASH_ROUND( v );
  b = v[ 0 ] ^ v[ 1 ] ^ v[ 2 ] ^ v[ 3 ];

  return b;
}
