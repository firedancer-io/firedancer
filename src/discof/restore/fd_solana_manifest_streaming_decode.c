#include "fd_solana_manifest_streaming_decode.h"
#include "../../flamenco/fd_flamenco_base.h"

#define FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, type ) \
  do {                                                         \
    uchar const * ptr = (uchar const *)buf;                    \
    if( ptr + sizeof(type) > buf + bufsz ) {                   \
        return -1;                                             \
    }                                                          \
    buf += sizeof(type);                                       \
  } while(0)

#define FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, type, dest ) \
  do {                                                          \
    uchar const * ptr = (uchar const *)buf;                     \
    if( ptr + sizeof(type) > buf + bufsz ) {                    \
        return -1;                                              \
    }                                                           \
    *(type *)dest = *(type const *)ptr;                         \
    buf += sizeof(type);                                        \
  } while(0)

#define FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, size ) \
  do {                                                      \
    uchar const * ptr = (uchar const *)buf;                 \
    if( ptr + size > buf + bufsz ) {                        \
        return -1;                                          \
    }                                                       \
    buf += size;                                            \
  } while(0)

#define FD_STREAMING_DECODE_SIZE( buf, bufsz, size, dest ) \
  do {                                                      \
    uchar const * ptr = (uchar const *)buf;                 \
    if( ptr + size > buf + bufsz ) {                        \
        return -1;                                          \
    }                                                       \
    uchar * dest_void = (uchar *)dest;                      \
    fd_memcpy( dest_void, ptr, size );                      \
    buf += size;                                            \
  } while(0)

#define FD_STREAMING_DECODE_SKIP_OPTION_PRIMITIVE( buf, bufsz, option_type ) \
do {                                                                         \
    uchar const * ptr = (uchar const *)buf;                                  \
    if( ptr + 1 > buf + bufsz ) {                                            \
        return -1;                                                           \
    }                                                                        \
    if( *ptr ) {                                                             \
      buf += 1;                                                              \
      FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, option_type );         \
    } else {                                                                 \
      buf += 1;                                                              \
    }                                                                        \
  } while(0)

#define FD_STREAMING_DECODE_OPTION_PRIMITIVE( buf, bufsz, option_type, dest ) \
  do {                                                                        \
      uchar * dest_void = (uchar *)dest;                                       \
      uchar const * ptr = (uchar const *)buf;                                 \
      if( ptr + 1 > buf + bufsz ) {                                           \
          return -1;                                                          \
      }                                                                       \
      if( *ptr ) {                                                            \
        *dest_void = (int)1;                                                  \
        dest_void += sizeof(int);                                             \
        buf += 1;                                                             \
        FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, option_type, dest_void );  \
      } else {                                                                \
        buf += 1;                                                             \
      }                                                                       \
    } while(0)

#define FD_STREAMING_DECODE_SKIP_OPTION_STATIC_SIZE( buf, bufsz, option_size ) \
  do {                                                                         \
      if( buf + 1 > buf + bufsz ) {                                            \
          return -1;                                                           \
      }                                                                        \
      if( *buf ) {                                                             \
        buf += 1;                                                              \
        if( buf + option_size > buf + bufsz ) {                                \
          return -1;                                                           \
        }                                                                      \
        buf += option_size;                                                    \
      } else {                                                                 \
        buf += 1;                                                              \
      }                                                                        \
    } while(0)

#define FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, vec_elem_size ) \
  do {                                                                           \
    ulong vec_len = (ulong)*( (ulong const *)buf );                              \
    FD_LOG_WARNING(("I got vector length %lu", vec_len));                        \
    if( buf + sizeof(ulong) + vec_elem_size * vec_len > buf + bufsz ) {          \
      return -1;                                                                 \
    }                                                                            \
    buf += sizeof(ulong);                                                        \
    buf += vec_elem_size * vec_len;                                              \
  } while(0)

int
fd_solana_manifest_streaming_decode( uchar * buf,
                                     ulong   bufsz,
                                     fd_snapshot_storages_t * storages,
                                     fd_snapshot_manifest_t * manifest ) {
  (void)storages;
  /* decode blockhash queue last hash index */
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );
  FD_STREAMING_DECODE_SKIP_OPTION_STATIC_SIZE( buf, bufsz, sizeof(fd_hash_t) );
  /* decode blockhash queue */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_hash_hash_age_pair_t) );
  FD_STREAMING_DECODE_SKIP_PRIMITIVE( buf, bufsz, ulong );

  /* decode ancestors_len */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_slot_pair_t) );
  /* decode bank hash and parent hash */
  FD_STREAMING_DECODE_SIZE( buf, bufsz, sizeof(fd_hash_t), &manifest->bank_hash );
  FD_STREAMING_DECODE_SIZE( buf, bufsz, sizeof(fd_hash_t), &manifest->parent_bank_hash );

  /* decode parent slot */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->parent_slot );

  /* decode hard forks */
  FD_STREAMING_DECODE_SKIP_VECTOR_STATIC_SIZE( buf, bufsz, sizeof(fd_slot_pair_t) );

  /* skip 5 ulongs in the bank */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 5*sizeof(ulong) );

  /* skip hashes per tick option */
  FD_STREAMING_DECODE_OPTION_PRIMITIVE( buf, bufsz, ulong, &manifest->has_hashes_per_tick );

  /* get ticks per slot */
  FD_STREAMING_DECODE_PRIMITIVE( buf, bufsz, ulong, &manifest->ticks_per_slot );

  /* skip ns per slot */
  FD_STREAMING_DECODE_SKIP_SIZE( buf, bufsz, 16UL );
//   FD_STREAMING_DECODE_UNIX_TIMESTAMP( buf, bufsz, ulong, &manifest->creation_time_ns );

  FD_LOG_WARNING(("I got manifest parent slot is %lu", manifest->parent_slot));
  FD_LOG_WARNING(("I got manifest bank hash is %s",
                  FD_BASE58_ENC_32_ALLOCA(&manifest->bank_hash)));
  FD_LOG_WARNING(("I got manifest parent bank hash is %s",
                  FD_BASE58_ENC_32_ALLOCA(&manifest->parent_bank_hash)));
  return 0;
}
