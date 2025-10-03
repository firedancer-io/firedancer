#include "fd_ssparse.h"

#include "../../../util/log/fd_log.h"
#include "../../../util/archive/fd_tar.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"

#include <stdio.h>

#define FD_SSPARSE_STATE_TAR_HEADER             (0)
#define FD_SSPARSE_STATE_SCROLL_TAR_HEADER      (1)
#define FD_SSPARSE_STATE_VERSION                (2)
#define FD_SSPARSE_STATE_MANIFEST               (3)
#define FD_SSPARSE_STATE_ACCOUNT_HEADER         (4)
#define FD_SSPARSE_STATE_ACCOUNT_DATA           (5)
#define FD_SSPARSE_STATE_ACCOUNT_PADDING        (6)
#define FD_SSPARSE_STATE_STATUS_CACHE           (7)
#define FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE (8)

struct fd_ssparse_private {
  int state;

  struct {
    int seen_zero_tar_frame;
    int seen_manifest;
    int seen_status_cache;
    int seen_version;
  } flags;

  uchar version[ 5UL ];

  struct {
    acc_vec_map_t * acc_vec_map;
    acc_vec_t *     acc_vec_pool;
  } manifest;

  struct {
    uchar header[ 512UL ];
    ulong file_bytes;
    ulong file_bytes_consumed;
    ulong header_bytes_consumed;
  } tar;

  struct {
    uchar header[ 136UL ];
    ulong header_bytes_consumed;
    ulong data_bytes_consumed;
    ulong data_len;
  } account;

  ulong acc_vec_bytes;
  ulong slot;
  ulong bytes_consumed;

  ulong seed;
  ulong max_acc_vecs;
  ulong magic;
};

FD_FN_CONST ulong
fd_ssparse_align( void ) {
  return FD_SSPARSE_ALIGN;
}

FD_FN_CONST ulong
fd_ssparse_footprint( ulong max_acc_vecs ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),   sizeof(fd_ssparse_t)                   );
  l = FD_LAYOUT_APPEND( l, acc_vec_pool_align(), acc_vec_pool_footprint( max_acc_vecs ) );
  l = FD_LAYOUT_APPEND( l, acc_vec_map_align(),  acc_vec_map_footprint( max_acc_vecs )  );
  return FD_LAYOUT_FINI( l, fd_ssparse_align() );
}

void *
fd_ssparse_new( void *  shmem,
                ulong   max_acc_vecs,
                ulong   seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ssparse_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ssparse_t * ssparse       = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),   sizeof(fd_ssparse_t)                   );
  void *         _acc_vec_pool = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_pool_align(), acc_vec_pool_footprint( max_acc_vecs ) );
  void *         _acc_vec_map  = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_map_align(),  acc_vec_map_footprint( max_acc_vecs )  );

  ssparse->manifest.acc_vec_pool = acc_vec_pool_join( acc_vec_pool_new( _acc_vec_pool, max_acc_vecs ) );
  FD_TEST( ssparse->manifest.acc_vec_pool );

  ssparse->manifest.acc_vec_map = acc_vec_map_join( acc_vec_map_new( _acc_vec_map, max_acc_vecs, seed ) );
  FD_TEST( ssparse->manifest.acc_vec_map );

  ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  fd_memset( &ssparse->flags, 0, sizeof(ssparse->flags) );

  ssparse->bytes_consumed = 0UL;
  ssparse->seed           = seed;
  ssparse->max_acc_vecs   = max_acc_vecs;

  ssparse->tar.header_bytes_consumed = 0UL;
  ssparse->tar.file_bytes_consumed   = 0UL;
  ssparse->tar.file_bytes            = 0UL;

  FD_COMPILER_MFENCE();
  ssparse->magic = FD_SSPARSE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ssparse;
}

fd_ssparse_t *
fd_ssparse_join( void * shssparse ) {
  if( FD_UNLIKELY( !shssparse ) ) {
    FD_LOG_WARNING(( "NULL shssparse" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shssparse, fd_ssparse_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shssparse" ));
    return NULL;
  }

  fd_ssparse_t * ssparse = (fd_ssparse_t *)shssparse;

  if( FD_UNLIKELY( ssparse->magic!=FD_SSPARSE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ssparse;
}

void
fd_ssparse_reset( fd_ssparse_t * ssparse ) {
  ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  fd_memset( &ssparse->flags, 0, sizeof(ssparse->flags) );
  ssparse->bytes_consumed                = 0UL;
  ssparse->tar.file_bytes_consumed       = 0UL;
  ssparse->account.header_bytes_consumed = 0UL;

  FD_SCRATCH_ALLOC_INIT( l, ssparse );
                         FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ssparse_t), sizeof(fd_ssparse_t)                            );
  void * _acc_vec_pool = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_pool_align(),  acc_vec_pool_footprint( ssparse->max_acc_vecs ) );
  void * _acc_vec_map  = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_map_align(),   acc_vec_map_footprint( ssparse->max_acc_vecs )  );

  acc_vec_pool_new( _acc_vec_pool, ssparse->max_acc_vecs );
  acc_vec_map_new( _acc_vec_map, ssparse->max_acc_vecs, ssparse->seed );
}

static int
advance_tar( fd_ssparse_t *                ssparse,
             uchar const *                 data,
             ulong                         data_sz,
             fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( data_sz, 512UL - ssparse->tar.header_bytes_consumed );
  if( FD_LIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  fd_memcpy( ssparse->tar.header+ssparse->tar.header_bytes_consumed, data, consume );
  ssparse->bytes_consumed            += consume;
  result->bytes_consumed              = consume;
  ssparse->tar.header_bytes_consumed += consume;

  if( FD_UNLIKELY( ssparse->tar.header_bytes_consumed<512UL ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  fd_tar_meta_t const * hdr = (fd_tar_meta_t const *)ssparse->tar.header;
  ssparse->tar.header_bytes_consumed = 0UL;

  /* "ustar\x00" and "ustar  \x00" (overlaps with version) are both
     valid values for magic.  These are POSIX ustar and OLDGNU versions
     respectively. */
  if( FD_UNLIKELY( memcmp( hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {
    int not_zero = 0;
    for( ulong i=0UL; i<512UL; i++ ) not_zero |= ssparse->tar.header[ i ];
    if( FD_UNLIKELY( not_zero ) ) {
      FD_LOG_WARNING(( "invalid tar header magic `%s`", hdr->magic ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    if( FD_LIKELY( ssparse->flags.seen_zero_tar_frame ) ) {
      if( FD_UNLIKELY( !ssparse->flags.seen_version || !ssparse->flags.seen_manifest || !ssparse->flags.seen_status_cache ) ) {
        FD_LOG_WARNING(( "unexpected end of file before version or manifest or status cache" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      return FD_SSPARSE_ADVANCE_DONE;
    }

    ssparse->flags.seen_zero_tar_frame = 1;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  if( FD_UNLIKELY( ssparse->flags.seen_zero_tar_frame ) ) {
    FD_LOG_WARNING(( "unexpected valid tar header after zero frame" ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->tar.file_bytes = fd_tar_meta_get_size( hdr );
  if( FD_UNLIKELY( ssparse->tar.file_bytes==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "invalid tar header size %lu", ssparse->tar.file_bytes ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( hdr->typeflag==FD_TAR_TYPE_DIR ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  if( FD_UNLIKELY( !fd_tar_meta_is_reg( hdr ) ) ) {
    FD_LOG_WARNING(( "invalid tar header type %d", hdr->typeflag ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }
  if( FD_UNLIKELY( !ssparse->tar.file_bytes ) ) {
    FD_LOG_WARNING(( "invalid tar header size %lu", ssparse->tar.file_bytes ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  /* TODO: Check every header field here for validity? */

  int desired_state;
  if( FD_LIKELY( !strncmp( hdr->name, "version", 7UL ) ) ) {
    desired_state = FD_SSPARSE_STATE_VERSION;
    if( FD_UNLIKELY( ssparse->tar.file_bytes!=5UL ) ) {
      FD_LOG_WARNING(( "invalid version file size %lu", ssparse->tar.file_bytes ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }
  } else if( FD_LIKELY( !strncmp( hdr->name, "accounts/", 9UL ) ) ) {
    ssparse->account.header_bytes_consumed = 0UL;
    desired_state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
    ulong id, slot;
    if( FD_UNLIKELY( sscanf( hdr->name, "accounts/%lu.%lu", &slot, &id )!=2 ) ) {
      FD_LOG_WARNING(( "invalid account append vec name %s", hdr->name ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    acc_vec_key_t key = { .slot = slot, .id = id };
    acc_vec_t const * acc_vec = acc_vec_map_ele_query_const( ssparse->manifest.acc_vec_map, &key, NULL, ssparse->manifest.acc_vec_pool );
    if( FD_UNLIKELY( !acc_vec ) ) {
      FD_LOG_WARNING(( "append vec %lu.%lu not found in manifest", slot, id ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    ssparse->acc_vec_bytes = acc_vec->file_sz;
    if( FD_UNLIKELY( ssparse->acc_vec_bytes>ssparse->tar.file_bytes ) ) {
      FD_LOG_WARNING(( "invalid append vec file size %lu > %lu", ssparse->acc_vec_bytes, ssparse->tar.file_bytes ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    ssparse->slot = slot;
  } else if( FD_LIKELY( !strncmp( hdr->name, "snapshots/status_cache", 22UL ) ) ) desired_state = FD_SSPARSE_STATE_STATUS_CACHE;
  else if( FD_LIKELY( !strncmp( hdr->name, "snapshots/", 10UL ) ) ) {
    desired_state = FD_SSPARSE_STATE_MANIFEST;
  } else {
    FD_LOG_WARNING(( "unexpected tar header name %s", hdr->name ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->tar.file_bytes_consumed = 0UL;

  switch( desired_state ) {
    case FD_SSPARSE_STATE_VERSION:
      if( FD_UNLIKELY( ssparse->flags.seen_version ) ) {
        FD_LOG_WARNING(( "unexpected duplicate verison file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->flags.seen_version = 1;
      ssparse->state = FD_SSPARSE_STATE_VERSION;
      break;
    case FD_SSPARSE_STATE_MANIFEST:
      if( FD_UNLIKELY( ssparse->flags.seen_manifest ) ) {
        FD_LOG_WARNING(( "unexpected duplicate manifest file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->flags.seen_manifest = 1;
      ssparse->state = FD_SSPARSE_STATE_MANIFEST;
      break;
    case FD_SSPARSE_STATE_ACCOUNT_HEADER:
      if( FD_UNLIKELY( !ssparse->flags.seen_manifest ) ) {
        FD_LOG_WARNING(( "unexpected account append vec file before manifest" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->account.header_bytes_consumed = 0UL;
      ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
      break;
    case FD_SSPARSE_STATE_STATUS_CACHE:
      if( FD_UNLIKELY( ssparse->flags.seen_status_cache ) ) {
        FD_LOG_WARNING(( "unexpected status cache file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->flags.seen_status_cache = 1;
      ssparse->state = FD_SSPARSE_STATE_STATUS_CACHE;
      break;
    default:
      FD_LOG_ERR(( "unexpected tar header desired state %d", desired_state ));
      break;
  }

  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_version( fd_ssparse_t *                ssparse,
                 uchar const *                 data,
                 ulong                         data_sz,
                 fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( data_sz, ssparse->tar.file_bytes-ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  fd_memcpy( ssparse->version+ssparse->tar.file_bytes_consumed, data, consume );

  ssparse->tar.file_bytes_consumed += consume;
  ssparse->bytes_consumed          += consume;
  result->bytes_consumed            = consume;

  if( FD_LIKELY( ssparse->tar.file_bytes_consumed<ssparse->tar.file_bytes ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  FD_TEST( ssparse->tar.file_bytes_consumed==ssparse->tar.file_bytes );
  FD_TEST( ssparse->tar.file_bytes_consumed==5UL );

  if( FD_UNLIKELY( memcmp( ssparse->version, "1.2.0", 5UL ) ) ) {
    FD_LOG_WARNING(( "invalid version file %s", ssparse->version ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_status_cache( fd_ssparse_t *                 ssparse,
                       uchar const *                 data,
                       ulong                         data_sz,
                       fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( data_sz, ssparse->tar.file_bytes-ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->tar.file_bytes_consumed += consume;
  ssparse->bytes_consumed          += consume;

  result->bytes_consumed            = consume;
  result->status_cache.data         = data;
  result->status_cache.data_sz      = consume;

  if( FD_LIKELY( ssparse->tar.file_bytes_consumed<ssparse->tar.file_bytes ) ) {
    return FD_SSPARSE_ADVANCE_STATUS_CACHE;
  }
  else { /* ssparse->tar.file_bytes_consumed==ssparse->tar.file_bytes */
    /* finished parsing status cache */
    ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
    if( FD_LIKELY( ssparse->flags.seen_manifest ) ) return FD_SSPARSE_ADVANCE_MANIFEST_AND_STATUS_CACHE_DONE;
    else                                            return FD_SSPARSE_ADVANCE_STATUS_CACHE;
  }
}

static int
advance_manifest( fd_ssparse_t *                ssparse,
                  uchar const *                 data,
                  ulong                         data_sz,
                  fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( data_sz, ssparse->tar.file_bytes-ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->tar.file_bytes_consumed += consume;
  ssparse->bytes_consumed          += consume;

  result->bytes_consumed           = consume;
  result->manifest.data            = data;
  result->manifest.data_sz         = consume;
  result->manifest.acc_vec_map     = ssparse->manifest.acc_vec_map;
  result->manifest.acc_vec_pool    = ssparse->manifest.acc_vec_pool;

  if( FD_LIKELY( ssparse->tar.file_bytes_consumed<ssparse->tar.file_bytes ) ) {
    return FD_SSPARSE_ADVANCE_MANIFEST;
  }
  else { /* ssparse->tar.file_bytes_consumed==ssparse->tar.file_bytes */
    /* finished parsing manifest */
    ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
    if( FD_LIKELY( ssparse->flags.seen_status_cache ) ) return FD_SSPARSE_ADVANCE_MANIFEST_AND_STATUS_CACHE_DONE;
    else                                                return FD_SSPARSE_ADVANCE_MANIFEST;
  }
}

static int
advance_next_tar( fd_ssparse_t *               ssparse,
                 uchar const *                 data,
                 ulong                         data_sz,
                 fd_ssparse_advance_result_t * result ) {
  (void)data;
  /* skip padding */
  ulong bytes_remaining    = fd_ulong_align_up( ssparse->bytes_consumed, 512UL ) - ssparse->bytes_consumed;
  ulong pad_sz             = bytes_remaining;
        pad_sz             = fd_ulong_min( pad_sz, data_sz );
  if( FD_UNLIKELY( !pad_sz && bytes_remaining ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->bytes_consumed += pad_sz;
  result->bytes_consumed   = pad_sz;
  bytes_remaining         -= pad_sz;

  if( FD_LIKELY( !bytes_remaining ) ) ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_account_header( fd_ssparse_t *                ssparse,
                        uchar const *                 data,
                        ulong                         data_sz,
                        fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( 136UL-ssparse->account.header_bytes_consumed, fd_ulong_min( data_sz, ssparse->acc_vec_bytes-ssparse->tar.file_bytes_consumed ) );

  if( FD_UNLIKELY( !consume ) ) {
    if( FD_LIKELY( ssparse->tar.file_bytes_consumed==ssparse->acc_vec_bytes ) ) {
      ssparse->state = FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE;
      return FD_SSPARSE_ADVANCE_AGAIN;
    } else {
      return FD_SSPARSE_ADVANCE_ERROR;
    }
  }

  if( FD_UNLIKELY( consume<136UL ) ) fd_memcpy( ssparse->account.header+ssparse->account.header_bytes_consumed, data, consume );

  ssparse->account.header_bytes_consumed += consume;
  ssparse->tar.file_bytes_consumed       += consume;
  ssparse->bytes_consumed                += consume;
  result->bytes_consumed                  = consume;

  if( FD_UNLIKELY( ssparse->account.header_bytes_consumed<136UL ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  uchar const * hdr = ssparse->account.header;
  if( FD_LIKELY( consume==136UL ) ) hdr = data;

  result->account_header.data_len = fd_ulong_load_8_fast( hdr+8UL );
  if( FD_UNLIKELY( result->account_header.data_len>FD_RUNTIME_ACC_SZ_MAX ) ) {
    FD_LOG_WARNING(( "invalid account header data length %lu", result->account_header.data_len ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  result->account_header.pubkey     = hdr+16UL;
  result->account_header.lamports   = fd_ulong_load_8_fast( hdr+48UL );
  result->account_header.rent_epoch = fd_ulong_load_8_fast( hdr+56UL );
  result->account_header.owner      = hdr+64UL;
  result->account_header.executable = hdr[ 96UL ];
  if( FD_UNLIKELY( result->account_header.executable>1 ) ) {
    char pubkey_str[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( result->account_header.pubkey, NULL, pubkey_str );
    FD_LOG_WARNING(( "invalid account header executable %d for account %s", result->account_header.executable, pubkey_str ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }
  result->account_header.hash       = hdr+104UL;
  result->account_header.slot       = ssparse->slot;

  ssparse->account.data_len            = result->account_header.data_len;
  ssparse->account.data_bytes_consumed = 0UL;
  ssparse->state = FD_SSPARSE_STATE_ACCOUNT_DATA;

  return FD_SSPARSE_ADVANCE_ACCOUNT_HEADER;
}

static int
advance_account_data( fd_ssparse_t *                ssparse,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t * result ) {
  if( FD_UNLIKELY( ssparse->account.data_bytes_consumed==ssparse->account.data_len ) ) {
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_PADDING;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ulong consume = fd_ulong_min( data_sz, ssparse->acc_vec_bytes-ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) {
    FD_LOG_WARNING(( "account data extends beyond append vec size" ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  consume = fd_ulong_min( consume, ssparse->account.data_len-ssparse->account.data_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->tar.file_bytes_consumed     += consume;
  ssparse->bytes_consumed              += consume;
  ssparse->account.data_bytes_consumed += consume;
  result->bytes_consumed                = consume;

  result->account_data.len  = consume;
  result->account_data.data = data;

  FD_TEST( ssparse->account.data_bytes_consumed<=ssparse->account.data_len );
  if( FD_LIKELY( ssparse->account.data_bytes_consumed==ssparse->account.data_len ) ) {
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_PADDING;
  }

  return FD_SSPARSE_ADVANCE_ACCOUNT_DATA;
}

static int
advance_account_padding( fd_ssparse_t *                ssparse,
                         uchar const *                 data,
                         ulong                         data_sz,
                         fd_ssparse_advance_result_t * result ) {
  (void)data;

  ulong pad_sz = fd_ulong_align_up( ssparse->tar.file_bytes_consumed, 8UL ) - ssparse->tar.file_bytes_consumed;
        pad_sz = fd_ulong_min( pad_sz, ssparse->acc_vec_bytes - ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !pad_sz ) ) {
    if( FD_LIKELY( ssparse->tar.file_bytes_consumed==ssparse->acc_vec_bytes ) ) ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
    else                                                                        ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;

    ssparse->account.header_bytes_consumed = 0UL;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ulong consume = fd_ulong_min( data_sz, pad_sz );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->tar.file_bytes_consumed += consume;
  ssparse->bytes_consumed          += consume;
  result->bytes_consumed            = consume;

  ulong remaining = fd_ulong_align_up( ssparse->tar.file_bytes_consumed, 8UL ) - ssparse->tar.file_bytes_consumed;
  if( FD_LIKELY( !remaining ) ) {
    ssparse->account.header_bytes_consumed = 0UL;
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
  }
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_account_garbage( fd_ssparse_t *                ssparse,
                         uchar const *                 data,
                         ulong                         data_sz,
                         fd_ssparse_advance_result_t * result ) {
  (void)data;
  ulong consume = fd_ulong_min( data_sz, ssparse->tar.file_bytes-ssparse->tar.file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) return FD_SSPARSE_ADVANCE_ERROR;

  ssparse->tar.file_bytes_consumed += consume;
  ssparse->bytes_consumed          += consume;
  result->bytes_consumed            = consume;

  if( FD_LIKELY( ssparse->tar.file_bytes_consumed<ssparse->tar.file_bytes ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_AGAIN;
}

int
fd_ssparse_advance( fd_ssparse_t *                ssparse,
                    uchar const *                 data,
                    ulong                         data_sz,
                    fd_ssparse_advance_result_t * result ) {
  result->bytes_consumed = 0UL;

  switch( ssparse->state ) {
    case FD_SSPARSE_STATE_TAR_HEADER:             return advance_tar( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_SCROLL_TAR_HEADER:      return advance_next_tar( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_VERSION:                return advance_version( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_MANIFEST:               return advance_manifest( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_HEADER:         return advance_account_header( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_DATA:           return advance_account_data( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_PADDING:        return advance_account_padding( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_STATUS_CACHE:           return advance_status_cache( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE: return advance_account_garbage( ssparse, data, data_sz, result );
    default: FD_LOG_ERR(( "invalid state %d", ssparse->state ));
  }
}

int
fd_ssparse_populate_acc_vec_map( fd_ssparse_t * ssparse,
                                 ulong *        slots,
                                 ulong *        ids,
                                 ulong *        file_szs,
                                 ulong          cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    acc_vec_key_t key = { .slot=slots[ i ], .id=ids[ i ] };
    if( FD_UNLIKELY( acc_vec_map_ele_query( ssparse->manifest.acc_vec_map, &key, NULL, ssparse->manifest.acc_vec_pool ) ) ) return -1;
    acc_vec_t * acc_vec = acc_vec_pool_ele_acquire( ssparse->manifest.acc_vec_pool );
    acc_vec->key.id   = ids[ i ];
    acc_vec->key.slot = slots[ i ];
    acc_vec->file_sz  = file_szs[ i ];
    acc_vec_map_ele_insert( ssparse->manifest.acc_vec_map, acc_vec, ssparse->manifest.acc_vec_pool );
  }
  return 0;
}
