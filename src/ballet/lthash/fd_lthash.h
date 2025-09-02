#ifndef HEADER_fd_src_ballet_lthash_fd_lthash_h
#define HEADER_fd_src_ballet_lthash_fd_lthash_h

/* LtHash provides APIs for lattice-based incremental hash based on blake3.
   https://eprint.iacr.org/2019/227
*/

#include "../blake3/fd_blake3.h"

#define FD_LTHASH_ALIGN       (64UL) /* sufficient for AVX512 */
#define FD_LTHASH_LEN_BYTES (2048UL)
#define FD_LTHASH_LEN_ELEMS (1024UL)

union __attribute__((aligned(FD_LTHASH_ALIGN))) fd_lthash_value {
  uchar  bytes[FD_LTHASH_LEN_BYTES];
  ushort words[FD_LTHASH_LEN_ELEMS];
};
typedef union fd_lthash_value fd_lthash_value_t;

FD_PROTOTYPES_BEGIN

static inline fd_lthash_value_t *
fd_lthash_fini( fd_blake3_t * sha,
                fd_lthash_value_t * hash ) {
  return fd_blake3_fini_2048( sha, hash->bytes );
}

static inline fd_lthash_value_t *
fd_lthash_zero( fd_lthash_value_t * r ) {
  return fd_memset( r->bytes, 0, FD_LTHASH_LEN_BYTES );
}

static inline int
fd_lthash_is_zero( fd_lthash_value_t const * r ) {
  for ( ulong i=0; i<FD_LTHASH_LEN_ELEMS; i++ ) {
    if( r->words[i] != 0 ) {
      return 0; /* not zero */
    }
  }

  return 1;
}

static inline fd_lthash_value_t *
fd_lthash_add( fd_lthash_value_t * restrict       r,
               fd_lthash_value_t const * restrict a ) {
  for ( ulong i=0; i<FD_LTHASH_LEN_ELEMS; i++ ) {
    r->words[i] = (ushort)( r->words[i] + a->words[i] );
  }
  return r;
}

static inline fd_lthash_value_t *
fd_lthash_sub( fd_lthash_value_t * restrict       r,
               fd_lthash_value_t const * restrict a ) {
  for ( ulong i=0; i<FD_LTHASH_LEN_ELEMS; i++ ) {
    r->words[i] = (ushort)( r->words[i] - a->words[i] );
  }
  return r;
}

#define FD_LTHASH_ENC_32_BUF( _x, _y ) __extension__({                   \
  if( FD_UNLIKELY( _x == NULL ) ) {                                      \
    strcpy(_y, "<NULL>");                                                \
  } else {                                                               \
    uchar _blake3_hash[FD_HASH_FOOTPRINT];                               \
    fd_blake3_hash(_x, FD_LTHASH_LEN_BYTES, _blake3_hash );              \
    fd_base58_encode_32( _blake3_hash, NULL, _y );                       \
  }                                                                      \
})

#define FD_LTHASH_ENC_32_ALLOCA( x ) __extension__({                     \
  char *_out = (char *)fd_alloca_check( 1UL, FD_BASE58_ENCODED_32_SZ );  \
  FD_LTHASH_ENC_32_BUF(x, _out);                                         \
  _out;                                                                  \
})

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_lthash_fd_lthash_h */
