#ifndef HEADER_fd_src_ballet_siphash13_fd_siphash13_h
#define HEADER_fd_src_ballet_siphash13_fd_siphash13_h

/* fd_siphash13 provides APIs for SipHash1-3.
   (1 compression round, 3 finalization rounds)

   This code is a modified version of https://github.com/antirez/siphash
   For further license info see NOTICE in the root of this repo.

   Copyright (c) 2012-2016 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
   Copyright (c) 2017 Salvatore Sanfilippo <antirez@gmail.com>
   Modified 2023 by Firedancer Contributors */

#include "../fd_ballet_base.h"

#define FD_SIPHASH13_ALIGN     (128UL)
#define FD_SIPHASH13_FOOTPRINT (128UL)

struct __attribute__((aligned(FD_SIPHASH13_ALIGN))) fd_siphash13_private {
  ulong v[ 4 ];
  ulong n;
  uchar buf[ 8 ];
};

typedef struct fd_siphash13_private fd_siphash13_t;

/* FD_SIPHASH_ROUND is the SipHash1-3 round function */

#define FD_SIPHASH_ROUND(v)                    \
  do {                                         \
    (v)[0] += (v)[1];                          \
    (v)[1] = fd_ulong_rotate_left((v)[1], 13); \
    (v)[1] ^= (v)[0];                          \
    (v)[0] = fd_ulong_rotate_left((v)[0], 32); \
    (v)[2] += (v)[3];                          \
    (v)[3] = fd_ulong_rotate_left((v)[3], 16); \
    (v)[3] ^= (v)[2];                          \
    (v)[0] += (v)[3];                          \
    (v)[3] = fd_ulong_rotate_left((v)[3], 21); \
    (v)[3] ^= (v)[0];                          \
    (v)[2] += (v)[1];                          \
    (v)[1] = fd_ulong_rotate_left((v)[1], 17); \
    (v)[1] ^= (v)[2];                          \
    (v)[2] = fd_ulong_rotate_left((v)[2], 32); \
  } while (0)

FD_PROTOTYPES_BEGIN

/* fd_siphash13_init starts a new SipHash1-3 calculation */

fd_siphash13_t *
fd_siphash13_init( fd_siphash13_t * sip,
                   ulong            k0,
                   ulong            k1 );

fd_siphash13_t *
fd_siphash13_append( fd_siphash13_t * sip,
                     uchar const *    data,
                     ulong            sz );

/* fd_siphash13_append_fast is an aligned-only version of
   fd_siphash13_append.  sip->n and sz must be multiplies of 8 bytes. */

fd_siphash13_t *
fd_siphash13_append_fast( fd_siphash13_t * sip,
                          uchar const *    data,
                          ulong            sz );

/* fd_siphash13_fini finishes a SipHash1-3 calculation.  Returns the
   hash value. */

ulong
fd_siphash13_fini( fd_siphash13_t * sip );

/* fd_siphash13_hash is a streamlined implementation of:

     fd_siphash13_t sip[1];
     return fd_siphash13_fini( fd_siphash13_append( fd_siphash13_init( sip ), data, sz ) );

   This can be faster for small message sizes. */

FD_FN_PURE ulong
fd_siphash13_hash( void const * data,
                   ulong        sz,
                   ulong        k0,
                   ulong        k1 );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_siphash13_fd_siphash13_h */
