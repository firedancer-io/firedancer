#ifndef HEADER_fd_src_ballet_lthash_fd_lthash_h
#define HEADER_fd_src_ballet_lthash_fd_lthash_h

/* LtHash provides APIs for lattice-based incremental hash based on blake3.
   https://eprint.iacr.org/2019/227
*/

#include "../fd_ballet_base.h"
#include "../blake3/fd_blake3.h"

#define FD_LTHASH_ALIGN     (FD_BLAKE3_ALIGN)
#define FD_LTHASH_LEN_BYTES (2048UL)
#define FD_LTHASH_LEN_ELEMS (1024UL)

union __attribute__((aligned(FD_LTHASH_ALIGN))) fd_lthash_value {
  uchar  bytes[FD_LTHASH_LEN_BYTES];
  ushort words[FD_LTHASH_LEN_ELEMS];
};
typedef union fd_lthash_value fd_lthash_value_t;

#define fd_lthash_t fd_blake3_t

FD_PROTOTYPES_BEGIN

#define fd_lthash_init fd_blake3_init
#define fd_lthash_append fd_blake3_append

static inline fd_lthash_value_t *
fd_lthash_fini( fd_lthash_t * sha,
                fd_lthash_value_t * hash ) {
  return fd_blake3_fini_varlen( sha, hash->bytes, FD_LTHASH_LEN_BYTES );
}

static inline fd_lthash_value_t *
fd_lthash_zero( fd_lthash_value_t * r ) {
  return fd_memset( r->bytes, 0, FD_LTHASH_LEN_BYTES );
}

static inline fd_lthash_value_t *
fd_lthash_add( fd_lthash_value_t * restrict       r,
               fd_lthash_value_t const * restrict a ) {
  for ( ulong i=0; i<FD_LTHASH_LEN_ELEMS; i++ ) {
    r->words[i] += a->words[i];
  }
  return r;
}

static inline fd_lthash_value_t *
fd_lthash_sub( fd_lthash_value_t * restrict       r,
               fd_lthash_value_t const * restrict a ) {
  for ( ulong i=0; i<FD_LTHASH_LEN_ELEMS; i++ ) {
    r->words[i] -= a->words[i];
  }
  return r;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_lthash_fd_lthash_h */
