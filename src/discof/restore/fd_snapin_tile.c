#include "fd_restore_base.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/archive/fd_tar.h"
#include "../../flamenco/runtime/fd_acc_mgr.h" /* FD_ACC_SZ_MAX */
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "stream/fd_stream_ctx.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define NAME        "SnapIn"
#define LINK_IN_MAX  1UL
#define BURST       16UL

#define SNAP_STATE_IGNORE       ((uchar)0)  /* ignore file content */
#define SNAP_STATE_TAR          ((uchar)1)  /* reading tar header (buffered) */
#define SNAP_STATE_MANIFEST     ((uchar)2)  /* reading manifest (buffered) */
#define SNAP_STATE_ACCOUNT_HDR  ((uchar)3)  /* reading account hdr (buffered) */
#define SNAP_STATE_ACCOUNT_DATA ((uchar)4)  /* reading account data (zero copy) */
#define SNAP_STATE_DONE         ((uchar)5)  /* expect no more data */

struct fd_snapshot_accv_key {
  ulong slot;
  ulong id;
};

typedef struct fd_snapshot_accv_key fd_snapshot_accv_key_t;

static const fd_snapshot_accv_key_t
fd_snapshot_accv_key_null = { 0UL, 0UL };

FD_FN_PURE static inline ulong
fd_snapshot_accv_key_hash( fd_snapshot_accv_key_t key ) {
  return fd_hash( 0x39c49607bf16463aUL, &key, sizeof(fd_snapshot_accv_key_t) );
}

struct fd_snapshot_accv_map {
  fd_snapshot_accv_key_t key;
  ulong                  sz;
  ulong                  hash;  /* use uint or ulong hash? */
};

typedef struct fd_snapshot_accv_map fd_snapshot_accv_map_t;

#define MAP_NAME              fd_snapshot_accv_map
#define MAP_T                 fd_snapshot_accv_map_t
#define MAP_LG_SLOT_CNT       23  /* 8.39 million */
#define MAP_KEY_T             fd_snapshot_accv_key_t
#define MAP_KEY_NULL          fd_snapshot_accv_key_null
#define MAP_KEY_INVAL(k)      ( ((k).slot==0UL) & ((k).id==0UL) )
#define MAP_KEY_EQUAL(k0,k1)  ( ((k0).slot==(k1).slot) & ((k0).id==(k1).id) )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_HASH_T            ulong
#define MAP_KEY_HASH(k0)      fd_snapshot_accv_key_hash(k0)
#include "../../util/tmpl/fd_map.c"

#define SNAP_FLAG_FAILED  1
#define SNAP_FLAG_BLOCKED 2
#define SNAP_FLAG_DONE    4

struct fd_snapin_tile {
  uchar state;
  uchar flags;
  uchar manifest_done;

  /* Stream input */

  fd_stream_frag_meta_ctx_t in_state; /* input mcache context */
  ulong *       in_sync;

  /* Frame buffer */

  uchar * buf;
  ulong   buf_ctr;  /* number of bytes allocated in buffer */
  ulong   buf_sz;   /* target buffer size (buf_ctr<buf_sz implies incomplete read) */
  ulong   buf_max;  /* byte capacity of buffer */

  /* Tar parser */

  ulong tar_file_rem; /* number of stream bytes in current TAR file */

  /* Snapshot file parser */

  ulong   accv_slot;  /* account vec slot */
  ulong   accv_id;    /* account vec index */
  ulong   accv_sz;    /* account vec size */
  fd_snapshot_accv_map_t * accv_map;

  /* Account defrag */

  ulong acc_sz;
  ulong acc_rem;  /* acc bytes pending write */
  ulong acc_pad;  /* padding size at end of account */

  /* Account insertion */

  fd_funk_t       funk[1];
  fd_funk_txn_t * funk_txn;
  uchar *         acc_data;
  ulong           inserted_accounts;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

struct fd_snapin_in {
  fd_stream_frag_meta_t const * mcache;
  uint                          depth;
  uint                          idx;
  ulong                         seq;
  ulong                         goff;
  fd_stream_frag_meta_t const * mline;
  ulong volatile * restrict     fseq;
  uint                          accum[6];
};

typedef struct fd_snapin_in fd_snapin_in_t;

static const fd_pubkey_t sentinel = {0};

struct fd_acc_chain_entry {
  fd_pubkey_t key;
  fd_funk_rec_t * rec;
  uint hash;
};
typedef struct fd_acc_chain_entry fd_acc_chain_entry_t;

static uint
fd_pubkey_hash( fd_pubkey_t key ) {
  return (uint)fd_hash( 0UL, key.key, sizeof(fd_pubkey_t) );
}

static int
fd_pubkey_inval( fd_pubkey_t key ) {
  return memcmp( key.uc, sentinel.uc, sizeof(fd_pubkey_t) )==0;
}

static int
fd_pubkey_equal( fd_pubkey_t a, fd_pubkey_t b ) {
  return memcmp( a.uc, b.uc, sizeof(fd_pubkey_t) );
}

#define MAP_NAME fd_accounts_in_chain
#define MAP_KEY_T fd_pubkey_t
#define MAP_T fd_acc_chain_entry_t
#define MAP_KEY_NULL sentinel
#define MAP_KEY_INVAL fd_pubkey_inval
#define MAP_KEY_EQUAL fd_pubkey_equal
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH fd_pubkey_hash
#define MAP_LG_SLOT_CNT 5
#include "../../util/tmpl/fd_map.c"

static void
fd_acc_key_from_rec( fd_funk_rec_t * rec, fd_pubkey_t * pubkey ) {
  fd_memcpy( pubkey, rec->pair.key, sizeof(fd_pubkey_t) );
}

void
fd_funk_dedup_accounts( fd_funk_t * funk ) {
  void * map_mem = fd_alloca_check( alignof(fd_acc_chain_entry_t), fd_accounts_in_chain_footprint() );
  fd_acc_chain_entry_t * accounts_map = fd_accounts_in_chain_join( fd_accounts_in_chain_new( map_mem ) );

  /* iterate though all chains and dedup the accounts based on slot */
  fd_funk_rec_map_t * rec_map = fd_funk_rec_map( funk );
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  ulong num_chains_with_multiple_accs = 0UL;
  ulong num_duplicates = 0UL;
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    fd_funk_rec_map_shmem_private_chain_t * chain =  fd_funk_rec_map_shmem_private_chain( rec_map->map, chain_idx );
    ulong ver_cnt = chain->ver_cnt;
    ulong ele_cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );

    if( ele_cnt > 1 ) {
      num_chains_with_multiple_accs++;
      for(
        fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
        !fd_funk_rec_map_iter_done( iter );
        iter = fd_funk_rec_map_iter_next( iter )
      ) {
        /* lookup record key in a local map */
        /* if not in the map, add to map */
        /* if already in map, check slot and flush the one with the lower slot */
        fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( iter );
        fd_pubkey_t key;
        fd_acc_key_from_rec( rec, &key );

        fd_account_meta_t * meta = fd_funk_val( rec, fd_funk_wksp( funk ) );
        fd_acc_chain_entry_t * found_rec = fd_accounts_in_chain_query(accounts_map, key, NULL );

        if( !found_rec ) {
          fd_acc_chain_entry_t * new_rec = fd_accounts_in_chain_insert( accounts_map, key );
          new_rec->rec = rec;
        } else {
          num_duplicates++;
          fd_account_meta_t * found_meta = fd_funk_val( rec, fd_funk_wksp( funk ) );
          if( found_meta->slot < meta->slot ) {
            fd_funk_val_flush( found_rec->rec, fd_funk_alloc( funk), fd_funk_wksp( funk ) );
            found_rec->rec = rec;
          } else if( meta->slot < found_meta->slot ) {
            fd_funk_val_flush( rec, fd_funk_alloc( funk), fd_funk_wksp( funk ) );
          }

        }
      }
      fd_accounts_in_chain_clear( accounts_map );
    }
  }
  FD_LOG_WARNING(("num chains with multiple accs: %lu, num_dups: %lu", num_chains_with_multiple_accs, num_duplicates));
}


static void
fd_snapin_process_snapshot_complete( fd_snapin_tile_t * ctx ) {
  FD_LOG_WARNING(("starting to dedup accounts!"));
  fd_funk_dedup_accounts( ctx->funk );
  FD_LOG_WARNING(("finished dedup accounts"));
}

static void
fd_snapin_shutdown( fd_snapin_tile_t * ctx ) {
  ctx->flags = SNAP_FLAG_DONE;

  // fd_snapin_process_snapshot_complete( ctx );

  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_LOG_WARNING(( "Finished parsing snapshot" ));

  for(;;) pause();
}

static void
fd_snapshot_restore_discard_buf( fd_snapin_tile_t * self ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;
}

static void *
fd_snapshot_restore_prepare_buf( fd_snapin_tile_t * self,
                                 ulong              sz ) {
  self->buf_ctr = 0UL;
  self->buf_sz  = 0UL;

  fd_snapshot_restore_discard_buf( self );
  if( FD_UNLIKELY( sz > self->buf_max ) ) {
    FD_LOG_WARNING(( "Alloc failed (need %lu bytes, have %lu)", sz, self->buf_max ));
    self->state = SNAP_FLAG_FAILED;
    return NULL;
  }

  return self->buf;
}

static int
fd_snapshot_expect_account_hdr( fd_snapin_tile_t * restore ) {

  ulong accv_sz = restore->accv_sz;
  if( accv_sz < sizeof(fd_solana_account_hdr_t) ) {
    if( FD_LIKELY( accv_sz==0UL ) ) {
      restore->state = SNAP_STATE_ACCOUNT_HDR;
      return 0;
    }
    FD_LOG_WARNING(( "encountered unexpected EOF while reading account header" ));
    restore->flags |= SNAP_FLAG_FAILED;
    return EINVAL;
  }

  restore->state   = SNAP_STATE_ACCOUNT_HDR;
  restore->buf_ctr = 0UL;
  restore->buf_sz  = sizeof(fd_solana_account_hdr_t);

  return 0;
}

static int
fd_snapshot_restore_accv_prepare( fd_snapin_tile_t *    const restore,
                                  fd_tar_meta_t const * const meta,
                                  ulong                 const real_sz ) {

  if( FD_UNLIKELY( !fd_snapshot_restore_prepare_buf( restore, sizeof(fd_solana_account_hdr_t) ) ) ) {
    FD_LOG_WARNING(( "Failed to allocate read buffer while restoring accounts from snapshot" ));
    return ENOMEM;
  }

  /* Parse file name */
  ulong id, slot;
  if( FD_UNLIKELY( sscanf( meta->name, "accounts/%lu.%lu", &slot, &id )!=2 ) ) {
    /* Ignore entire file if file name invalid */
    restore->state = SNAP_STATE_IGNORE;
    return 0;
  }

  /* Lookup account vec file size */
  fd_snapshot_accv_key_t key = { .slot = slot, .id = id };
  fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_query( restore->accv_map, key, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    /* Ignore account vec files that are not explicitly mentioned in the
        manifest. */
    FD_LOG_DEBUG(( "Ignoring %s (sz %lu)", meta->name, real_sz ));
    restore->state = SNAP_STATE_IGNORE;
    return 0;
  }
  ulong sz = rec->sz;

  /* Validate the supposed file size against real size */
  if( FD_UNLIKELY( sz > real_sz ) ) {
    FD_LOG_WARNING(( "AppendVec %lu.%lu is %lu bytes long according to manifest, but actually only %lu bytes",
                     slot, id, sz, real_sz ));
    restore->flags |= SNAP_FLAG_FAILED;
    return EINVAL;
  }
  restore->accv_sz   = sz;
  restore->accv_slot = slot;
  restore->accv_id   = id;

  /* Prepare read of account header */
  FD_LOG_DEBUG(( "Loading account vec %s", meta->name ));
  return fd_snapshot_expect_account_hdr( restore );
}


/* fd_snapshot_restore_manifest_prepare prepares for consumption of the
   snapshot manifest. */

static int
fd_snapshot_restore_manifest_prepare( fd_snapin_tile_t * restore,
                                      ulong              sz ) {
  /* Only read once */
  if( restore->manifest_done ) {
    FD_LOG_WARNING(( "Snapshot file contains multiple manifests" ));
    restore->state = SNAP_STATE_IGNORE;
    return 0;
  }

  /* We don't support streaming manifest deserialization yet.  Thus,
     buffer the whole manifest in one place. */
  if( FD_UNLIKELY( !fd_snapshot_restore_prepare_buf( restore, sz ) ) ) {
    restore->flags |= SNAP_FLAG_FAILED;
    return ENOMEM;
  }

  restore->state  = SNAP_STATE_MANIFEST;
  restore->buf_sz = sz;

  return 0;
}

static void
restore_file( void *                restore_,
              fd_tar_meta_t const * meta,
              ulong                 sz ) {
  fd_snapin_tile_t * restore = restore_;

  restore->buf_ctr = 0UL;  /* reset buffer */
  restore->state   = SNAP_STATE_IGNORE;

  if( (sz==0UL) | (!fd_tar_meta_is_reg( meta )) ) return;

  /* Detect account vec files.  These are files that contain a vector
     of accounts in Solana Labs "AppendVec" format. */
  assert( sizeof("accounts/")<FD_TAR_NAME_SZ );
  if( 0==strncmp( meta->name, "accounts/", sizeof("accounts/")-1) ) {
    if( FD_UNLIKELY( !restore->manifest_done ) ) {
      FD_LOG_WARNING(( "Unsupported snapshot: encountered AppendVec before manifest" ));
      restore->flags |= SNAP_FLAG_FAILED;
      return;
    }
    fd_snapshot_restore_accv_prepare( restore, meta, sz );
  } else if( fd_memeq( meta->name, "snapshots/status_cache", sizeof("snapshots/status_cache") ) ) {
    /* TODO */
  } else if(0==strncmp( meta->name, "snapshots/", sizeof("snapshots/")-1 ) ) {
    fd_snapshot_restore_manifest_prepare( restore, sz );
  }

}

static uchar const *
snapshot_read_buffered( fd_snapin_tile_t * restore,
                        uchar const *      buf,
                        ulong              bufsz ) {
  /* Should not be called if read is complete */
  FD_TEST( restore->buf_ctr < restore->buf_sz );

  /* Determine number of bytes to buffer */
  ulong sz = restore->buf_sz - restore->buf_ctr;
  if( sz>bufsz ) sz = bufsz;

  /* Append to buffer */
  fd_memcpy( restore->buf + restore->buf_ctr, buf, sz );
  restore->buf_ctr += sz;

  return buf+sz;
}

FD_FN_PURE static inline int
snapshot_read_is_complete( fd_snapin_tile_t const * restore ) {
  return restore->buf_ctr == restore->buf_sz;
}

static int
snapshot_is_duplicate_account( fd_snapin_tile_t *  restore,
                               fd_pubkey_t const * account_key ) {
  /* Check if account exists */
  fd_account_meta_t const * rec_meta = fd_funk_find_account( restore->funk, account_key );
  if( rec_meta )
    if( rec_meta->slot > restore->accv_slot ) 
      return 1;
  return 0;
}

static int
snapshot_insert_account2( fd_snapin_tile_t *              restore,
  fd_pubkey_t const *             account_key,
  fd_solana_account_hdr_t const * hdr ) {
  FD_TXN_ACCOUNT_DECL( rec );

  fd_account_meta_t * meta = fd_funk_insert_account( restore->funk, account_key, hdr );
  rec->vt->set_meta_mutable(rec, meta );

  rec->vt->set_data_len( rec, hdr->meta.data_len );
  rec->vt->set_slot( rec, restore->accv_slot );
  rec->vt->set_hash( rec, &hdr->hash );
  rec->vt->set_info( rec, &hdr->info );
  /* TODO: do we still need rent logic here? see fd_snapshot_restore_account_hdr */
  restore->acc_data = rec->vt->get_data_mut( rec );
  restore->inserted_accounts++;
  return 0;
}

static int
snapshot_restore_account_hdr( fd_snapin_tile_t * restore ) {
  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( restore->buf );
  if( FD_UNLIKELY( hdr->meta.data_len > FD_ACC_SZ_MAX ) ) {
    FD_LOG_ERR(( "account data size (%lu) exceeds max (%lu) (possible memory corruption?)", hdr->meta.data_len, FD_ACC_SZ_MAX ));
  }

  ulong data_sz    = hdr->meta.data_len;
  restore->acc_sz  = data_sz;
  restore->acc_rem = data_sz;
  restore->acc_pad = fd_ulong_align_up( data_sz, 8UL ) - data_sz;

  if( FD_UNLIKELY( data_sz>(10UL<<20) ) ) {
    FD_LOG_ERR(( "Oversize account found (%lu bytes)", data_sz ));
  }
  
  fd_pubkey_t const * account_key = fd_type_pun_const( hdr->meta.pubkey );
  if( !snapshot_is_duplicate_account( restore, account_key) ) {
    snapshot_insert_account2( restore, account_key, hdr );
  }

  /* Next step */
  if( data_sz == 0UL ) {
    return fd_snapshot_expect_account_hdr( restore );
  }

  restore->state   = SNAP_STATE_ACCOUNT_DATA;
  restore->buf_ctr = 0UL;
  restore->buf_sz  = 0UL;
  return 0;
}

static uchar const *
snapshot_read_account_hdr_chunk( fd_snapin_tile_t * restore,
                                 uchar const *      buf,
                                 ulong              bufsz ) {
  if( !restore->accv_sz ) {
    /* Reached end of AppendVec */
    restore->state   = SNAP_STATE_IGNORE;
    restore->buf_ctr = restore->buf_sz = 0UL;
    return buf;
  }
  bufsz = fd_ulong_min( bufsz, restore->accv_sz );

  uchar const * buf_next = snapshot_read_buffered( restore, buf, bufsz );
  ulong hdr_read = (ulong)(buf_next-buf);
  restore->accv_sz -= hdr_read;
  bufsz            -= hdr_read;

  ulong peek_sz = 0UL;
  if( FD_LIKELY( snapshot_read_is_complete( restore ) ) ) {
    if( FD_UNLIKELY( 0!=snapshot_restore_account_hdr( restore ) ) ) {
      return buf; /* parse error */
    }
    peek_sz = fd_ulong_min( restore->acc_rem, bufsz );
  }

  restore->acc_rem -= peek_sz;
  restore->accv_sz -= peek_sz;
  buf_next         += peek_sz;

  return buf_next;
}

static uchar const *
snapshot_read_account_chunk( fd_snapin_tile_t * restore,
                             uchar const *      buf,
                             ulong              bufsz ) {

  ulong chunk_sz = fd_ulong_min( restore->acc_rem, bufsz );
  if( FD_LIKELY( restore->acc_data ) ) {
    fd_memcpy( restore->acc_data, buf, chunk_sz );
    restore->acc_data += chunk_sz;
  }
  if( FD_UNLIKELY( chunk_sz > restore->accv_sz ) )
    FD_LOG_CRIT(( "OOB account vec read: chunk_sz=%lu accv_sz=%lu", chunk_sz, restore->accv_sz ));

  if( FD_LIKELY( chunk_sz ) ) {

    restore->acc_rem -= chunk_sz;
    restore->accv_sz -= chunk_sz;
    buf              += chunk_sz;
    bufsz            -= chunk_sz;

  }

  if( restore->acc_rem == 0UL ) {
    ulong pad_sz = fd_ulong_min( fd_ulong_min( restore->acc_pad, bufsz ), restore->accv_sz );
    buf              += pad_sz;
    bufsz            -= pad_sz;
    restore->acc_pad -= pad_sz;
    restore->accv_sz -= pad_sz;

    if( restore->accv_sz == 0UL ) {
      restore->state = SNAP_STATE_IGNORE;
      return buf;
    }
    if( restore->acc_pad == 0UL ) {
      return (0==fd_snapshot_expect_account_hdr( restore )) ? buf : NULL;
    }
  }

  return buf;
}


/* fd_snapshot_accv_index populates the index of account vecs.  This
   index will be used when loading accounts.  Returns errno-compatible
   error code. */

static int
fd_snapshot_accv_index( fd_snapshot_accv_map_t *               map,
                        fd_solana_accounts_db_fields_t const * fields ) {

  for( ulong i=0UL; i < fields->storages_len; i++ ) {

    fd_snapshot_slot_acc_vecs_t * slot = &fields->storages[ i ];

    for( ulong j=0UL; j < slot->account_vecs_len; j++ ) {
      fd_snapshot_acc_vec_t * accv = &slot->account_vecs[ j ];

      /* Insert new AppendVec */
      fd_snapshot_accv_key_t key = { .slot = slot->slot, .id = accv->id };
      fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_insert( map, key );
      if( FD_UNLIKELY( !rec ) ) {
        FD_LOG_WARNING(( "fd_snapshot_accv_map_insert failed" ));
        return ENOMEM;
      }

      /* Remember size */
      rec->sz = accv->file_sz;
    }

  }

  return 0;
}

/* snapshot_restore_manifest imports a snapshot manifest into the
   given slot context.  Also populates the accv index.  Destroys the
   existing bank structure. */

static void
snapshot_restore_manifest( fd_snapin_tile_t * restore ) {

  /* Decode manifest placing dynamic data structures onto slot context
     heap.  Once the epoch context heap is separated out, we need to
     revisit this.

     This is horrible.  Plenty of room for optimization, including:
     - Streaming decoding
     - Fixing the decoder (does 2 walks in decode_footprint, decode)
     - Unpack directly into slot_ctx */

  long dt = -fd_log_wallclock();

  fd_bincode_decode_ctx_t decode = {
    .data    = restore->buf,
    .dataend = restore->buf + restore->buf_sz
  };

  ulong total_sz = 0UL;
  int err = fd_solana_manifest_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_solana_manifest_decode_footprint failed (%d)", err ));
  }

  uchar * scratch    = (uchar *)fd_ulong_align_up( (ulong)decode.dataend, fd_solana_manifest_align() );
  ulong   scratch_sz = (ulong)( restore->buf + restore->buf_max - scratch );
  if( FD_UNLIKELY( total_sz > scratch_sz ) ) {
    FD_LOG_ERR(( "Cannot decode snapshot. Insufficient scratch buffer size (need %lu, have %lu bytes)",
                 (ulong)scratch + total_sz - (ulong)restore->buf, restore->buf_max ));
  }
  fd_solana_manifest_t * manifest = fd_solana_manifest_decode( scratch, &decode );

  char acc_hash_cstr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( manifest->accounts_db.bank_hash_info.accounts_hash.uc, NULL, acc_hash_cstr );
  if( manifest->bank_incremental_snapshot_persistence ) {
    FD_LOG_ERR(( "Incremental snapshots not yet supported TODO" ));
  } else {
    FD_LOG_NOTICE(( "Full snapshot acc_hash=%s", acc_hash_cstr ));
  }

  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Snapshot manifest decode took %.2g seconds", (double)dt/1e9 ));

  /* Move over accounts DB fields */

  fd_solana_accounts_db_fields_t accounts_db = manifest->accounts_db;
  fd_memset( &manifest->accounts_db, 0, sizeof(fd_solana_accounts_db_fields_t) );

  /* Remember slot number */

  //ulong slot = manifest->bank.slot;

  /* Copy objects into slot context */

  //if( restore->cb_manifest ) {
  //  err = restore->cb_manifest( restore->cb_manifest_ctx, manifest, restore->spad );
  //}

  /* Read AccountVec map */

  if( FD_LIKELY( !err ) ) {
    err = fd_snapshot_accv_index( restore->accv_map, &accounts_db );
  }

  /* Discard buffer to reclaim heap space */

  fd_snapshot_restore_discard_buf( restore );

  restore->manifest_done = 1;
}

/* snapshot_read_manifest_chunk reads partial manifest content. */

static uchar const *
snapshot_read_manifest_chunk( fd_snapin_tile_t * restore,
                              uchar const *      buf,
                              ulong              bufsz ) {
  uchar const * end = snapshot_read_buffered( restore, buf, bufsz );
  if( snapshot_read_is_complete( restore ) ) {
    snapshot_restore_manifest( restore );
    restore->state = SNAP_STATE_IGNORE;
  }
  return end;
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapin_tile_t), fd_snapshot_accv_map_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),    sizeof(fd_snapin_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  l = FD_LAYOUT_APPEND( l, 16UL,                         tile->snapin.scratch_sz          );
  return l;
}

static fd_snapin_tile_t *
scratch_init( void *                 mem,
              fd_topo_tile_t const * tile ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, scratch_align() ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapin_tile_t * ctx          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void *             accv_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  void *             scratch_mem  = FD_SCRATCH_ALLOC_APPEND( l, 16UL, tile->snapin.scratch_sz );

  fd_memset( ctx, 0, sizeof(fd_snapin_tile_t) );
  ctx->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem ) );
  FD_TEST( ctx->accv_map );
  ctx->buf = scratch_mem;

  return ctx;
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  /* FIXME check link names */

  if( FD_UNLIKELY( !tile->snapin.scratch_sz ) ) FD_LOG_ERR(( "scratch_sz param not set" ));

  fd_snapin_tile_t * ctx = scratch_init( fd_topo_obj_laddr( topo, tile->tile_obj_id ), tile );
  if( FD_UNLIKELY( !ctx ) ) FD_LOG_ERR(( "scratch_init failed" ));

  /* Init state */

  ctx->state         = SNAP_STATE_TAR;
  ctx->flags         = 0;
  ctx->manifest_done = 0;

  /* Join stream input */

  FD_TEST( fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ) ) );
  ctx->in_state.in_buf  = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->in_state.in_skip = 0UL;
  ctx->in_sync = fd_mcache_seq_laddr( topo->links[ tile->in_link_id[ 0 ] ].mcache );

  /* Join frame buffer */

  ctx->buf_sz  = 0UL;
  ctx->buf_ctr = 0UL;
  ctx->buf_max = tile->snapin.scratch_sz;

  /* join funk */
  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /* IDK what to put here right now */
  ctx->funk_txn = NULL;
  ctx->inserted_accounts = 0UL;
}

static void
tar_process_hdr( fd_snapin_tile_t * reader,
                 uchar const *      cur ) {

  fd_tar_meta_t const * hdr = (fd_tar_meta_t const *)reader->buf;

  /* "ustar\x00" and "ustar  \x00" (overlaps with version) are both
     valid values for magic.  These are POSIX ustar and OLDGNU versions
     respectively. */
  if( FD_UNLIKELY( 0!=memcmp( hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {

    /* Detect EOF.  A TAR EOF is marked by 1024 bytes of zeros.
       We abort after 512 bytes. */
    int not_zero=0;
    for( ulong i=0UL; i<sizeof(fd_tar_meta_t); i++ )
      not_zero |= reader->buf[ i ];
    if( !not_zero ) {
      cur += sizeof(fd_tar_meta_t);
      fd_snapin_shutdown( reader );
      return;
    }
    /* Not an EOF, so must be a protocol error */
    ulong goff = (ulong)cur - reader->in_state.goff_translate - sizeof(fd_tar_meta_t);
    FD_LOG_WARNING(( "Invalid tar header magic at goff=0x%lx", goff ));
    FD_LOG_HEXDUMP_WARNING(( "Tar header", hdr, sizeof(fd_tar_meta_t) ));
    reader->flags |= SNAP_FLAG_FAILED;
    return;
  }

  ulong file_sz = fd_tar_meta_get_size( hdr );
  if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Failed to parse file size in tar header" ));
    reader->flags |= SNAP_FLAG_FAILED;
    return;
  }
  reader->tar_file_rem = file_sz;
  reader->buf_ctr      = (ushort)0U;

  /* Call back to recipient */
  restore_file( reader, hdr, file_sz );
}

static uchar const *
tar_read_hdr( fd_snapin_tile_t * reader,
              uchar const *      cur,
              ulong              bufsz ) {
  uchar const * end = cur+bufsz;

  /* Skip padding */
  if( reader->buf_ctr==0UL ) {
    ulong  goff   = (ulong)cur - reader->in_state.goff_translate;
    ulong  pad_sz = fd_ulong_align_up( goff, 512UL ) - goff;
           pad_sz = fd_ulong_min( pad_sz, (ulong)( end-cur ) );
    cur += pad_sz;
  }

  /* Determine number of bytes to read */
  long chunk_sz = (long)sizeof(fd_tar_meta_t) - (long)reader->buf_ctr;
  FD_TEST( chunk_sz>=0L );
  if( end-cur < chunk_sz ) chunk_sz = end-cur;

  /* Copy to header */
  fd_memcpy( reader->buf + reader->buf_ctr, cur, (ulong)chunk_sz );
  cur             +=        chunk_sz;
  reader->buf_ctr += (ulong)chunk_sz;

  /* Handle complete header */
  if( FD_LIKELY( reader->buf_ctr == sizeof(fd_tar_meta_t) ) ) {
    tar_process_hdr( reader, cur );
  }

  return cur;
}

static uchar const *
snapshot_read_discard( fd_snapin_tile_t * restore,
                       uchar const *      buf,
                       ulong              bufsz ) {
  ulong avail = fd_ulong_min( bufsz, restore->tar_file_rem );
  return buf + avail;
}

static uchar const *
restore_chunk1( fd_snapin_tile_t * restore,
                uchar const *      buf,
                ulong              bufsz ) {
  if( FD_UNLIKELY( restore->state==SNAP_STATE_TAR ) ) {
    return tar_read_hdr( restore, buf, bufsz );
  }
  bufsz = fd_ulong_min( bufsz, restore->tar_file_rem );

  uchar const * buf_next = NULL;
  switch( restore->state ) {
  case SNAP_STATE_IGNORE:
    buf_next = snapshot_read_discard          ( restore, buf, bufsz );
    break;
  case SNAP_STATE_MANIFEST:
    buf_next = snapshot_read_manifest_chunk   ( restore, buf, bufsz );
    break;
  case SNAP_STATE_ACCOUNT_HDR:
    buf_next = snapshot_read_account_hdr_chunk( restore, buf, bufsz );
    break;
  case SNAP_STATE_ACCOUNT_DATA:
    buf_next = snapshot_read_account_chunk    ( restore, buf, bufsz );
    break;
  default:
    FD_LOG_ERR(( "Invalid parser state %u (this is a bug)", restore->state ));
  }

  ulong consumed = (ulong)buf_next - (ulong)buf;
  if( FD_UNLIKELY( consumed>bufsz ) ) FD_LOG_CRIT(( "Buffer overflow (consumed=%lu bufsz=%lu)", consumed, bufsz ));
  restore->tar_file_rem -= consumed;
  if( restore->tar_file_rem==0UL ) {
    restore->buf_ctr = 0UL;
    restore->buf_sz  = 0UL;
    restore->state   = SNAP_STATE_TAR;
  }
  return buf_next;
}

/* on_stream_frag consumes an incoming stream data fragment.  This frag
   may be up to the dcache size (e.g. 8 MiB), therefore could contain
   thousands of accounts.  This function will publish a message for each
   account to consumers.  Slow consumers may cause backpressure and
   force this function to exit early (before all accounts in this frag
   were published).  In that case, this function is called repeatedly
   once the backpressure condition resolves (see in_skip). */

static int
on_stream_frag( void *                        _ctx,
                fd_stream_reader_t *          reader FD_PARAM_UNUSED,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  fd_snapin_tile_t * ctx = fd_type_pun( _ctx );

  if( FD_UNLIKELY( ctx->flags ) ) {
    if( FD_UNLIKELY( ctx->flags & SNAP_FLAG_FAILED ) ) FD_LOG_ERR(( "Failed to restore snapshot" ));
    if( FD_UNLIKELY( ctx->flags & SNAP_FLAG_DONE ) ) {
      *sz = frag->sz;
      return 1;
    }
    return 0;
  }

  uchar const * const chunk0 = ctx->in_state.in_buf + frag->loff;
  uchar const * const chunk1 = chunk0 + frag->sz;
  uchar const * const start  = chunk0 + ctx->in_state.in_skip;
  uchar const *       cur    = start;

  ctx->in_state.goff_translate = (ulong)chunk0 - frag->goff;

  int consume_frag = 1;
  for(;;) {
    if( FD_UNLIKELY( cur>=chunk1 ) ) {
      ctx->in_state.in_skip = 0U;
      break;
    }
    cur = restore_chunk1( ctx, cur, (ulong)( chunk1-cur ) );
    if( FD_UNLIKELY( ctx->flags ) ) {
      if( FD_UNLIKELY( ctx->flags & SNAP_FLAG_FAILED ) ) {
        FD_LOG_ERR(( "Failed to restore snapshot" ));
      }
    }
  }

  ulong consumed_sz = (ulong)( cur-start );
  *sz  = consumed_sz;

  /* write inserted accounts number to in_sync[3] */
  FD_COMPILER_MFENCE();
  ctx->in_sync[3] = ctx->inserted_accounts;
  FD_COMPILER_MFENCE();

  return consume_frag;
}

/* fd_snapin_in_update gets called periodically synchronize flow control
   credits back to the stream producer.  Also updates link in metrics. */

static void
fd_snapin_in_update( fd_stream_reader_t * in ) {
  fd_stream_reader_update_upstream( in );
}

__attribute__((noinline)) static void
fd_snapin_run1(
    fd_snapin_tile_t *         ctx,
    fd_stream_ctx_t *          stream_ctx
) {
  fd_stream_ctx_run( stream_ctx,
    ctx,
    NULL,
    fd_snapin_in_update,
    NULL,
    NULL,
    NULL,
    on_stream_frag );
}

FD_FN_UNUSED static void
fd_snapin_run( fd_topo_t *      topo,
               fd_topo_tile_t * tile ) {
  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void * ctx_mem = fd_alloca_check( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_footprint( topo, tile ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile );
  FD_TEST( stream_ctx );
  fd_snapin_run1( ctx, stream_ctx );
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapshot_restore_SnapIn = {
  .name              = "SnapIn",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_snapin_run,
};
#endif

#undef LINK_IN_MAX
#undef BURST
