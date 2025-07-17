#include "fd_ssparse.h"

#include "../../../flamenco/types/fd_types.h"
#include "../../../util/archive/fd_tar.h"

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

struct acc_vec_key {
  ulong slot;
  ulong id;
};

typedef struct acc_vec_key acc_vec_key_t;

struct acc_vec {
  acc_vec_key_t key;
  ulong         file_sz;

  ulong         map_next;
  ulong         map_prev;

  ulong         pool_next;
};

typedef struct acc_vec acc_vec_t;

#define POOL_NAME  pool
#define POOL_T     acc_vec_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ulong

#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME          acc_vec_map
#define MAP_ELE_T         acc_vec_t
#define MAP_KEY_T         acc_vec_key_t
#define MAP_KEY           key
#define MAP_IDX_T         ulong
#define MAP_NEXT          map_next
#define MAP_PREV          map_prev
#define MAP_KEY_HASH(k,s) fd_hash( s, k, sizeof(acc_vec_key_t) )
#define MAP_KEY_EQ(k0,k1) ( ((k0)->slot==(k1)->slot) && ((k0)->id==(k1)->id) )

#include "../../../util/tmpl/fd_map_chain.c"

struct fd_ssparse_private {
  int state;

  int seen_zero_tar_frame;
  int seen_manifest;
  int seen_status_cache;
  int seen_version;

  ulong file_bytes;
  ulong file_bytes_consumed;
  ulong acc_vec_bytes;
  ulong account_header_bytes_consumed;
  ulong account_data_bytes_consumed;

  ulong bytes_consumed;

  uchar version[ 5UL ];

  uchar account_header[ 136UL ];
  ulong account_data_len;
  uchar tar_header[ 512UL ];

  uchar   manifest_bytes[ 1UL<<31UL ];
  uchar * payload;
  ulong   payload_sz;

  acc_vec_t * pool;
  acc_vec_map_t * acc_vec_map;

  ulong seed;

  ulong magic;
};

FD_FN_CONST ulong
fd_ssparse_align( void ) {
  return FD_SSPARSE_ALIGN;
}

FD_FN_CONST ulong
fd_ssparse_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),  sizeof(fd_ssparse_t)               );
  l = FD_LAYOUT_APPEND( l, pool_align(),        pool_footprint( 1UL<<23UL )        );
  l = FD_LAYOUT_APPEND( l, acc_vec_map_align(), acc_vec_map_footprint( 1UL<<22UL ) );
  return FD_LAYOUT_FINI( l, fd_ssparse_align() );
}

void *
fd_ssparse_new( void *  shmem,
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
  fd_ssparse_t * ssparse  = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),  sizeof(fd_ssparse_t)               );
  void * _pool            = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),        pool_footprint( 1UL<<23UL )        );
  void * _acc_vec_map     = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_map_align(), acc_vec_map_footprint( 1UL<<22UL ) );

  ssparse->pool = pool_join( pool_new( _pool, 1UL<<23UL ) );
  FD_TEST( ssparse->pool );

  ssparse->acc_vec_map = acc_vec_map_join( acc_vec_map_new( _acc_vec_map, 65536UL, seed ) );
  FD_TEST( ssparse->acc_vec_map );

  ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  ssparse->seen_zero_tar_frame = 0;
  ssparse->seen_manifest = 0;
  ssparse->seen_version = 0;
  ssparse->seen_status_cache = 0;

  ssparse->bytes_consumed = 0UL;

  ssparse->seed = seed;

  ssparse->magic = FD_SSPARSE_MAGIC;

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
fd_ssparse_reset( fd_ssparse_t * ssparse,
                  uchar *        payload,
                  ulong          payload_sz ) {
  ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  ssparse->seen_zero_tar_frame = 0;
  ssparse->seen_manifest = 0;
  ssparse->seen_version = 0;
  ssparse->seen_status_cache = 0;

  ssparse->bytes_consumed = 0UL;

  ssparse->payload    = payload;
  ssparse->payload_sz = payload_sz;

  FD_TEST( acc_vec_map_new( ssparse->acc_vec_map, 65536UL, ssparse->seed ) );
  FD_TEST( pool_new( ssparse->pool, 1UL<<23UL ) );
}

static int
advance_tar( fd_ssparse_t *                ssparse,
             uchar const *                 data,
             ulong                         data_sz,
             fd_ssparse_advance_result_t * result ) {
  ulong bytes_remaining = 512UL-(ssparse->bytes_consumed%512UL);
  ulong consume = fd_ulong_min( data_sz, bytes_remaining );
  FD_TEST( consume );

  fd_memcpy( ssparse->tar_header+(ssparse->bytes_consumed%512UL), data, consume );
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_UNLIKELY( ssparse->bytes_consumed%512UL ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  fd_tar_meta_t const * hdr = (fd_tar_meta_t const *)ssparse->tar_header;

  /* "ustar\x00" and "ustar  \x00" (overlaps with version) are both
     valid values for magic.  These are POSIX ustar and OLDGNU versions
     respectively. */
  if( FD_UNLIKELY( memcmp( hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {
    int not_zero = 0;
    for( ulong i=0UL; i<512UL; i++ ) not_zero |= ssparse->tar_header[ i ];
    if( FD_UNLIKELY( not_zero ) ) {
      FD_LOG_WARNING(( "invalid tar header magic `%s`", hdr->magic ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    if( FD_LIKELY( ssparse->seen_zero_tar_frame ) ) {
      if( FD_UNLIKELY( !ssparse->seen_version || !ssparse->seen_manifest || !ssparse->seen_status_cache ) ) {
        FD_LOG_WARNING(( "unexpected end of file before version or manifest or status cache" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      return FD_SSPARSE_ADVANCE_DONE;
    }

    ssparse->seen_zero_tar_frame = 1;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  if( FD_UNLIKELY( ssparse->seen_zero_tar_frame ) ) {
    FD_LOG_WARNING(( "unexpected valid tar header after zero frame" ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->file_bytes = fd_tar_meta_get_size( hdr );
  if( FD_UNLIKELY( ssparse->file_bytes==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "invalid tar header size %lu", ssparse->file_bytes ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( hdr->typeflag==FD_TAR_TYPE_DIR ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  if( FD_UNLIKELY( !fd_tar_meta_is_reg( hdr ) ) ) {
    FD_LOG_WARNING(( "invalid tar header type %d", hdr->typeflag ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }
  if( FD_UNLIKELY( !ssparse->file_bytes ) ) {
    FD_LOG_WARNING(( "invalid tar header size %lu", ssparse->file_bytes ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  /* TODO: Check every header field here for validity? */

  int desired_state;
  if( FD_LIKELY( !strncmp( hdr->name, "version", 7UL ) ) ) {
    desired_state = FD_SSPARSE_STATE_VERSION;
    if( FD_UNLIKELY( ssparse->file_bytes!=5UL ) ) {
      FD_LOG_WARNING(( "invalid version file size %lu", ssparse->file_bytes ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }
  } else if( FD_LIKELY( !strncmp( hdr->name, "accounts/", 9UL ) ) ) {
    ssparse->account_header_bytes_consumed = 0UL;
    desired_state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
    ulong id, slot;
    if( FD_UNLIKELY( sscanf( hdr->name, "accounts/%lu.%lu", &slot, &id )!=2 ) ) {
      FD_LOG_WARNING(( "invalid account append vec name %s", hdr->name ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    acc_vec_key_t key = { .slot = slot, .id = id };
    acc_vec_t const * acc_vec = acc_vec_map_ele_query_const( ssparse->acc_vec_map, &key, NULL, ssparse->pool );
    if( FD_UNLIKELY( !acc_vec ) ) {
      FD_LOG_WARNING(( "append vec %lu.%lu not found in manifest", slot, id ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }

    ssparse->acc_vec_bytes = acc_vec->file_sz;
    if( FD_UNLIKELY( ssparse->acc_vec_bytes>ssparse->file_bytes ) ) {
      FD_LOG_WARNING(( "invalid append vec file size %lu > %lu", ssparse->acc_vec_bytes, ssparse->file_bytes ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }
  } else if( FD_LIKELY( !strncmp( hdr->name, "snapshots/status_cache", 22UL ) ) ) desired_state = FD_SSPARSE_STATE_STATUS_CACHE;
  else if( FD_LIKELY( !strncmp( hdr->name, "snapshots/", 10UL ) ) ) {
    desired_state = FD_SSPARSE_STATE_MANIFEST;
    if( FD_UNLIKELY( !ssparse->file_bytes || ssparse->file_bytes>sizeof(ssparse->manifest_bytes) ) ) {
      FD_LOG_WARNING(( "invalid manifest file size %lu", ssparse->file_bytes ));
      return FD_SSPARSE_ADVANCE_ERROR;
    }
  } else {
    FD_LOG_WARNING(( "unexpected tar header name %s", hdr->name ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->file_bytes_consumed = 0UL;

  switch( desired_state ) {
    case FD_SSPARSE_STATE_VERSION:
      if( FD_UNLIKELY( ssparse->seen_version ) ) {
        FD_LOG_WARNING(( "unexpected duplicate verison file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->seen_version = 1;
      ssparse->state = FD_SSPARSE_STATE_VERSION;
      break;
    case FD_SSPARSE_STATE_MANIFEST:
      if( FD_UNLIKELY( ssparse->seen_manifest ) ) {
        FD_LOG_WARNING(( "unexpected duplicate manifest file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->seen_manifest = 1;
      ssparse->state = FD_SSPARSE_STATE_MANIFEST;
      break;
    case FD_SSPARSE_STATE_ACCOUNT_HEADER:
      if( FD_UNLIKELY( !ssparse->seen_manifest ) ) {
        FD_LOG_WARNING(( "unexpected account append vec file before manifest" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->account_header_bytes_consumed = 0UL;
      ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
      break;
    case FD_SSPARSE_STATE_STATUS_CACHE:
      if( FD_UNLIKELY( !ssparse->seen_manifest || ssparse->seen_status_cache ) ) {
        FD_LOG_WARNING(( "unexpected status cache file" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      ssparse->seen_status_cache = 1;
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
  ulong consume = fd_ulong_min( data_sz, ssparse->file_bytes-ssparse->file_bytes_consumed );
  FD_TEST( consume );

  fd_memcpy( ssparse->version+ssparse->file_bytes_consumed, data, consume );

  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_LIKELY( ssparse->file_bytes_consumed<ssparse->file_bytes ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  FD_TEST( ssparse->file_bytes_consumed==ssparse->file_bytes );
  FD_TEST( ssparse->file_bytes_consumed==5UL );

  if( FD_UNLIKELY( memcmp( ssparse->version, "1.2.0", 5UL ) ) ) {
    FD_LOG_WARNING(( "invalid version file %s", ssparse->version ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_manifest( fd_ssparse_t *                ssparse,
                  uchar const *                 data,
                  ulong                         data_sz,
                  fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( data_sz, ssparse->file_bytes-ssparse->file_bytes_consumed );
  FD_TEST( consume );

  fd_memcpy( ssparse->manifest_bytes+ssparse->file_bytes_consumed, data, consume );
  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_LIKELY( ssparse->file_bytes_consumed<ssparse->file_bytes ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  fd_bincode_decode_ctx_t decode = {
    .data    = ssparse->manifest_bytes,
    .dataend = ssparse->manifest_bytes+ssparse->file_bytes,
  };

  ulong total_sz = 0UL;
  int err = fd_solana_manifest_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "failed to decode manifest footprint: %d", err ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( total_sz<ssparse->file_bytes ) ) {
    FD_LOG_WARNING(( "invalid manifest, total size %lu is less than file size %lu", total_sz, ssparse->file_bytes ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ulong decoded_manifest_offset = fd_ulong_align_up( sizeof(fd_solana_manifest_t), FD_SOLANA_MANIFEST_GLOBAL_ALIGN );
  if( FD_UNLIKELY( decoded_manifest_offset+total_sz>ssparse->payload_sz ) ) {
    FD_LOG_WARNING(( "invalid manifest, total size %lu exceeds max decoded manifest size %lu", decoded_manifest_offset+total_sz, ssparse->payload_sz ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  fd_solana_manifest_global_t * manifest = fd_solana_manifest_decode_global( ssparse->payload+decoded_manifest_offset, &decode );

  result->manifest.size = total_sz;
  result->manifest.slot = manifest->bank.slot;

  fd_snapshot_slot_acc_vecs_global_t * slots = fd_solana_accounts_db_fields_storages_join( &manifest->accounts_db );
  for( ulong i=0UL; i<manifest->accounts_db.storages_len; i++ ) {
    fd_snapshot_slot_acc_vecs_global_t * slot = &slots[ i ];
    fd_snapshot_acc_vec_t * account_vecs = fd_snapshot_slot_acc_vecs_account_vecs_join( slot );
    for( ulong j=0UL; j<slot->account_vecs_len; j++ ) {
      fd_snapshot_acc_vec_t * accv = &account_vecs[ j ];

      if( FD_UNLIKELY( !pool_free( ssparse->pool ) ) ) {
        FD_LOG_WARNING(( "invalid manifest, too many append vecs" ));
        return FD_SSPARSE_ADVANCE_ERROR;
      }

      acc_vec_t * vec = pool_ele_acquire( ssparse->pool );
      vec->key.slot = slot->slot;
      vec->key.id = accv->id;
      vec->file_sz = accv->file_sz;

      FD_TEST( acc_vec_map_ele_insert( ssparse->acc_vec_map, vec, ssparse->pool ) );
      
      acc_vec_key_t key = { .slot = vec->key.slot, .id = vec->key.id };
      acc_vec_t const * existing = acc_vec_map_ele_query_const( ssparse->acc_vec_map, &key, NULL, ssparse->pool );
      FD_TEST( existing );
    }
  }

  ssparse->state = FD_SSPARSE_STATE_SCROLL_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_MANIFEST;
}

static int
advace_next_tar( fd_ssparse_t *                ssparse,
                 uchar const *                 data,
                 ulong                         data_sz,
                 fd_ssparse_advance_result_t * result ) {
  (void)data;

  if( FD_UNLIKELY( !(ssparse->bytes_consumed%512UL ) ) ) {
    ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ulong bytes_remaining = 512UL-(ssparse->bytes_consumed%512UL);
  ulong consume = fd_ulong_min( data_sz, bytes_remaining );
  FD_TEST( consume );

  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;
  
  if( FD_LIKELY( !(ssparse->bytes_consumed%512UL ) ) ) ssparse->state = FD_SSPARSE_STATE_TAR_HEADER;
  return FD_SSPARSE_ADVANCE_AGAIN;
}

static int
advance_account_header( fd_ssparse_t *                ssparse,
                        uchar const *                 data,
                        ulong                         data_sz,
                        fd_ssparse_advance_result_t * result ) {
  ulong consume = fd_ulong_min( 136UL-ssparse->account_header_bytes_consumed, fd_ulong_min( data_sz, ssparse->acc_vec_bytes-ssparse->file_bytes_consumed ) );

  if( FD_UNLIKELY( !consume ) ) {
    FD_TEST( ssparse->file_bytes_consumed==ssparse->acc_vec_bytes );
    ssparse->state = FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_UNLIKELY( consume<136UL ) ) fd_memcpy( ssparse->account_header+ssparse->account_header_bytes_consumed, data, consume );
  ssparse->account_header_bytes_consumed +=consume;
  if( FD_UNLIKELY( ssparse->account_header_bytes_consumed<136UL ) ) return FD_SSPARSE_ADVANCE_AGAIN;

  uchar const * hdr = ssparse->account_header;
  if( FD_LIKELY( consume==136UL ) ) hdr = data;

  result->account_header.data_len   = fd_ulong_load_8_fast( hdr+8UL );
  if( FD_UNLIKELY( result->account_header.data_len>10UL*(1UL<<20UL) ) ) {
    FD_LOG_WARNING(( "invalid account header data length %lu", result->account_header.data_len ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  result->account_header.pubkey     = hdr+40UL;
  result->account_header.lamports   = fd_ulong_load_8_fast( hdr+48UL );
  result->account_header.rent_epoch = fd_ulong_load_8_fast( hdr+56UL );
  result->account_header.owner      = hdr+64UL;
  result->account_header.executable = hdr[ 96UL ];
  if( FD_UNLIKELY( result->account_header.executable>1 ) ) {
    FD_LOG_WARNING(( "invalid account header executable %d %lu %lu", result->account_header.executable, result->account_header.lamports, result->account_header.rent_epoch ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }
  result->account_header.hash       = hdr+104UL;

  ssparse->account_data_len = result->account_header.data_len;
  ssparse->account_data_bytes_consumed = 0UL;
  ssparse->state = FD_SSPARSE_STATE_ACCOUNT_DATA;

  return FD_SSPARSE_ADVANCE_ACCOUNT_HEADER;
}

static int
advance_account_data( fd_ssparse_t *                ssparse,
                      uchar const *                 data,
                      ulong                         data_sz,
                      fd_ssparse_advance_result_t * result ) {
  if( FD_UNLIKELY( ssparse->account_data_bytes_consumed==ssparse->account_data_len ) ) {
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_PADDING;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ulong consume = fd_ulong_min( data_sz, ssparse->acc_vec_bytes-ssparse->file_bytes_consumed );
  if( FD_UNLIKELY( !consume ) ) {
    FD_LOG_WARNING(( "account data extends beyond append vec size" ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  consume = fd_ulong_min( consume, ssparse->account_data_len-ssparse->account_data_bytes_consumed );
  FD_TEST( consume );

  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  ssparse->account_data_bytes_consumed += consume;
  result->bytes_consumed = consume;

  result->account_data.len = consume;
  result->account_data.data = data;

  FD_TEST( ssparse->account_data_bytes_consumed<=ssparse->account_data_len );
  if( FD_UNLIKELY( ssparse->file_bytes_consumed==ssparse->acc_vec_bytes ) ) {
    ssparse->state = FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE;
  } else if( FD_LIKELY( ssparse->account_data_bytes_consumed==ssparse->account_data_len ) ) {
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

  if( FD_UNLIKELY( !(ssparse->file_bytes_consumed%8UL ) ) ) {
    ssparse->account_header_bytes_consumed = 0UL;
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ulong bytes_remaining = 8UL-(ssparse->file_bytes_consumed%8UL);
  if( FD_UNLIKELY( ssparse->file_bytes_consumed+bytes_remaining>ssparse->acc_vec_bytes ) ) {
    FD_LOG_WARNING(( "account padding extends beyond append vec size" ));
    return FD_SSPARSE_ADVANCE_ERROR;
  }

  ulong consume = fd_ulong_min( data_sz, bytes_remaining );
  if( FD_LIKELY( !consume ) ) {
    ssparse->account_header_bytes_consumed = 0UL;
    ssparse->state = FD_SSPARSE_STATE_ACCOUNT_HEADER;
    return FD_SSPARSE_ADVANCE_AGAIN;
  }

  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_LIKELY( !(ssparse->file_bytes_consumed%8UL ) ) ) {
    ssparse->account_header_bytes_consumed = 0UL;
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

  ulong consume = fd_ulong_min( data_sz, ssparse->file_bytes-ssparse->file_bytes_consumed );

  ssparse->file_bytes_consumed += consume;
  ssparse->bytes_consumed += consume;
  result->bytes_consumed = consume;

  if( FD_LIKELY( ssparse->file_bytes_consumed<ssparse->file_bytes ) ) return FD_SSPARSE_ADVANCE_AGAIN;

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
    case FD_SSPARSE_STATE_SCROLL_TAR_HEADER:      return advace_next_tar( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_VERSION:                return advance_version( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_MANIFEST:               return advance_manifest( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_HEADER:         return advance_account_header( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_DATA:           return advance_account_data( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_ACCOUNT_PADDING:        return advance_account_padding( ssparse, data, data_sz, result );
    case FD_SSPARSE_STATE_STATUS_CACHE:
      ssparse->state = FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE; /* Ignored for now */
      return FD_SSPARSE_ADVANCE_AGAIN;
    case FD_SSPARSE_STATE_SCROLL_ACCOUNT_GARBAGE: return advance_account_garbage( ssparse, data, data_sz, result );
    default: FD_LOG_ERR(( "invalid state %d", ssparse->state ));
  }
}
