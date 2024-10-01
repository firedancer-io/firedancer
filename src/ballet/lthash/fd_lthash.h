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

#define FD_LTHASH_VALUE_ALIGN         (FD_LTHASH_ALIGN)
#define FD_LTHASH_VALUE_FOOTPRINT     sizeof(fd_lthash_value_t)

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

static inline void
fd_lthash_hash( fd_lthash_value_t const *  r, uchar hash[ static 32] ) {
  ulong *p = (ulong *) r->bytes;
  for ( ulong i=0; i<(FD_LTHASH_LEN_BYTES / sizeof(ulong)); i++ ) {
    if (*p++ != 0) {
      fd_blake3_t b3[1];
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, r->bytes, FD_LTHASH_LEN_BYTES  );
      fd_blake3_fini  ( b3, hash );
      return;
    }
  }

  fd_memset(hash, 0, 32);
}

#define FD_LTHASH_ENC_32_BUF( _x, _y ) __extension__({                   \
  if( FD_UNLIKELY( _x == NULL ) ) {                                      \
    strcpy(_y, "<NULL>");                                                \
  } else {                                                               \
    uchar _hash[32];                                                     \
    fd_lthash_hash(_x, _hash);                                           \
    fd_base58_encode_32( _hash, NULL, _y );                              \
  }                                                                      \
})

#define FD_LTHASH_ENC_32_ALLOCA( x ) __extension__({                     \
  char *_out = (char *)fd_alloca_check( 1UL, FD_BASE58_ENCODED_32_SZ );  \
  FD_LTHASH_ENC_32_BUF(x, _out);                                         \
  _out;                                                                  \
})

#define FD_LTHASH_ADD( x, y, z ) __extension__({                         \
   char _b[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(x, _b);                                          \
   fd_lthash_add( x, y );                                                \
   char _c[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(y, _c);                                          \
   char _d[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(x, _d);                                          \
   FD_LOG_NOTICE(("%s, fd_lthash_add, %s, %s, %s", z, _b, _c, _d));      \
  })

#define FD_LTHASH_SUB( x, y, z ) __extension__({                         \
   char _b[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(x, _b);                                          \
   fd_lthash_sub( x, y );                                                \
   char _c[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(y, _c);                                          \
   char _d[FD_BASE58_ENCODED_32_SZ];                                     \
   FD_LTHASH_ENC_32_BUF(x, _d);                                          \
   FD_LOG_NOTICE(("%s, fd_lthash_sub, %s, %s, %s", z, _b, _c, _d));      \
  })

#define FD_LTHASH_ADD_2( x, y ) __extension__({                            \
   fd_lthash_add( x, y );                                                \
  })

#define FD_LTHASH_SUB_2( x, y ) __extension__({                            \
   fd_lthash_sub( x, y );                                                \
  })


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_lthash_fd_lthash_h */
