#include "fd_restore_base.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/archive/fd_tar.h"
#include "../../flamenco/types/fd_types.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

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

struct fd_snapin_tile {
  uchar state;
  uchar flags;
  uchar manifest_done;

  /* Stream input */

  uchar const * in_base;
  ulong         goff_translate;
  ulong         loff_translate;
  ulong         in_skip;

  /* Frame buffer */

  uchar const * buf_start;
  uchar * buf;
  ulong   buf_ctr;  /* number of bytes allocated in buffer */
  ulong   buf_sz;   /* target buffer size (buf_ctr<buf_sz implies incomplete read) */
  ulong   buf_max;  /* byte capacity of buffer */
  ulong   pad_sz;

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

  /* Account output */

  fd_stream_frag_meta_t * out_mcache;

  ulong out_seq_max;
  ulong out_seq;
  ulong out_cnt;
  ulong out_depth;
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
                        uchar const *           buf,
                        ulong                   bufsz ) {
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
snapshot_restore_account_hdr( fd_snapin_tile_t * restore ) {
  fd_solana_account_hdr_t const * hdr = fd_type_pun_const( restore->buf );
  // char key_cstr[ FD_BASE58_ENCODED_32_SZ ];
  // fd_base58_encode_32( hdr->meta.pubkey, NULL, key_cstr );
  // FD_LOG_WARNING(("snapin: pubkey is %s", key_cstr));
  // FD_LOG_WARNING(("data len is %lu", hdr->meta.data_len));
  // uchar empty_pubkey[32];
  // fd_memset(empty_pubkey, 0, 32);
  // if( memcmp(hdr->meta.pubkey, empty_pubkey, 32) == 0) {
  //   FD_LOG_HEXDUMP_WARNING(( "acc hdr", hdr, sizeof(fd_solana_account_hdr_t) ));
  //   FD_LOG_HEXDUMP_WARNING(( "acc hdr", (uchar *)hdr-(10*1024*1024)-136, 2048 ));
  //   FD_LOG_HEXDUMP_WARNING(( "Tar header", restore->buf_start, sizeof(fd_tar_meta_t) ));
  // }

  // char target_pubkey[FD_BASE58_ENCODED_32_SZ] = "4exkj2LqTNssGv9r4QjjRt36s9K8PybRr47puEz2vWmg";
  // if( memcmp( key_cstr, target_pubkey,FD_BASE58_ENCODED_32_SZ)==0) {
  //   FD_LOG_WARNING(("THIS IS THE PUBKEY"));
  //   FD_LOG_HEXDUMP_WARNING(( "DATA: ", hdr, 512 ));
  // }

  ulong data_sz    = hdr->meta.data_len;
  restore->acc_sz  = data_sz;
  restore->acc_rem = data_sz;
  restore->acc_pad = fd_ulong_align_up( data_sz, 8UL ) - data_sz;

  if( FD_UNLIKELY( data_sz>(10UL<<20) ) ) {
    FD_LOG_ERR(( "Oversize account found (%lu bytes)", data_sz ));
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

  int som = restore->buf_ctr == 0UL;

  ulong frag_goff = (ulong)buf - restore->goff_translate;
  ulong frag_loff = (ulong)buf - restore->loff_translate;

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

  int eom = bufsz > restore->acc_rem;

  /* Publish header-only fragment or header+data fragment.
     If data was included, skip ahead.  (Combining header+data into the
     same fragment reduces the amount of descriptor frags published.) */

  fd_mcache_publish_stream(
      restore->out_mcache,
      restore->out_depth,
      restore->out_seq,
      frag_goff,
      frag_loff,
      hdr_read + peek_sz,
      fd_frag_meta_ctl( 0UL, som, eom, 0 )
  );
  restore->out_seq  = fd_seq_inc( restore->out_seq, 1UL );
  restore->out_cnt += !!som;
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
  if( FD_UNLIKELY( chunk_sz > restore->accv_sz ) )
    FD_LOG_CRIT(( "OOB account vec read: chunk_sz=%lu accv_sz=%lu", chunk_sz, restore->accv_sz ));

  if( FD_LIKELY( chunk_sz ) ) {

    int eom = restore->acc_rem == chunk_sz;

    fd_mcache_publish_stream(
        restore->out_mcache,
        restore->out_depth,
        restore->out_seq,
        (ulong)buf - restore->goff_translate,
        (ulong)buf - restore->loff_translate,
        chunk_sz,
        fd_frag_meta_ctl( 0UL, 0, eom, 0 )
    );

    restore->out_seq  = fd_seq_inc( restore->out_seq, 1UL );
    restore->acc_rem -= chunk_sz;
    restore->accv_sz -= chunk_sz;
    buf              += chunk_sz;
    bufsz            -= chunk_sz;

  }

  if( restore->acc_rem == 0UL ) {
    ulong pad_sz = fd_ulong_min( fd_ulong_min( restore->acc_pad, bufsz ), restore->accv_sz );
    // FD_LOG_WARNING(("pad sz is %lu", pad_sz));
    buf              += pad_sz;
    bufsz            -= pad_sz;
    restore->acc_pad -= pad_sz;
    restore->accv_sz -= pad_sz;

    if( restore->accv_sz == 0UL ) {
      restore->state = SNAP_STATE_IGNORE;
      return buf;
    }
    if( restore->acc_pad == 0UL ) {
      // FD_LOG_WARNING(("accv_sz is %lu", restore->accv_sz));
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

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `FileRd` tile" ));

  if( FD_UNLIKELY( tile->in_cnt !=1UL ) ) FD_LOG_ERR(( "tile `FileRd` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `FileRd` has %lu outs, expected 1", tile->out_cnt ));
  /* FIXME check link names */

  if( FD_UNLIKELY( !tile->snapin.scratch_sz ) ) FD_LOG_ERR(( "scratch_sz param not set" ));

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapin_tile_t * ctx          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void *             accv_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_accv_map_align(), fd_snapshot_accv_map_footprint() );
  void *             scratch_mem  = FD_SCRATCH_ALLOC_APPEND( l, 16UL, tile->snapin.scratch_sz );
  fd_memset( ctx, 0, sizeof(fd_snapin_tile_t) );

  /* Init state */

  ctx->state         = SNAP_STATE_TAR;
  ctx->flags         = 0;
  ctx->manifest_done = 0;

  /* Join stream input */

  uchar const * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ) );
  ctx->in_base             = out_dcache;
  ctx->in_skip             = 0UL;

  /* Join frame buffer */

  ctx->buf           = scratch_mem;
  ctx->buf_sz        = 0UL;
  ctx->buf_ctr       = 0UL;
  ctx->buf_max       = tile->snapin.scratch_sz;

  /* Join snapshot file parser */

  ctx->accv_map = fd_snapshot_accv_map_join( fd_snapshot_accv_map_new( accv_map_mem ) );
  FD_TEST( ctx->accv_map );

  /* Join account output */

  ctx->out_mcache  = fd_type_pun( topo->links[ tile->out_link_id[ 0 ] ].mcache );
  ctx->out_seq_max = 0UL;
  ctx->out_seq     = 0UL;
  ctx->out_depth   = fd_mcache_depth( ctx->out_mcache->f );

}

static void
during_housekeeping( fd_snapin_tile_t * ctx ) {
  (void)ctx;
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  (void)ctx;
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
      return;
    }

    /* Not an EOF, so must be a protocol error */
    ulong goff = (ulong)cur - reader->goff_translate - sizeof(fd_tar_meta_t);
    FD_LOG_WARNING(( "Invalid tar header magic at goff=0x%lx", goff ));
    FD_LOG_HEXDUMP_WARNING(( "Tar header", hdr, sizeof(fd_tar_meta_t) ));
    reader->flags |= SNAP_FLAG_FAILED;
    FD_LOG_WARNING(("FAILED"));
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
  if( reader->pad_sz==0UL ) {
    ulong  goff   = (ulong)cur - reader->goff_translate;
    reader->pad_sz = fd_ulong_align_up( goff, 512UL ) - goff;
    ulong pad_sz_cur = fd_ulong_min( reader->pad_sz, (ulong)( end-cur ) );
    reader->pad_sz  -= pad_sz_cur;
    cur += pad_sz_cur;
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
__attribute__((unused)) restore_chunk1( fd_snapin_tile_t * restore,
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
on_stream_frag( fd_snapin_tile_t *            ctx,
                fd_snapin_in_t *              in,
                fd_stream_frag_meta_t const * frag,
                ulong *                       read_sz ) {
  if( FD_UNLIKELY( ctx->flags ) ) {
    if( FD_UNLIKELY( ctx->flags & SNAP_FLAG_FAILED ) ) FD_LOG_ERR(( "Failed to restore snapshot" ));
    return 0;
  }

  (void)in;
  uchar const * const chunk0 = ctx->in_base + frag->loff;
  uchar const * const chunk1 = chunk0 + frag->sz;
  uchar const * const start  = chunk0 + ctx->in_skip;
  uchar const *       cur    = start;

  ctx->goff_translate = (ulong)chunk0 - frag->goff;
  ctx->loff_translate = (ulong)chunk0 - frag->loff;
  ctx->buf_start = ctx->in_base + frag->loff;

  int consume_frag = 1;
  for(;;) {
    if( FD_UNLIKELY( cur>=chunk1 ) ) {
      ctx->in_skip = 0U;
      break;
    }
    cur = restore_chunk1( ctx, cur, (ulong)( chunk1-cur ) );
    if( FD_UNLIKELY( ctx->flags ) ) {
      if( FD_UNLIKELY( ctx->flags & SNAP_FLAG_FAILED ) ) {
        FD_LOG_ERR(( "Failed to restore snapshot" ));
      }
      FD_LOG_ERR(( "blocked" ));
      FD_LOG_WARNING(("snapin: blocked on act alc!!"));
      consume_frag = 0; /* retry this frag */
      ulong consumed_sz = (uint)( cur-start );
      ctx->in_skip += consumed_sz;
      break;
    }
  }

  ulong consumed_sz = (ulong)( cur-start );
  *read_sz  = consumed_sz;
  in->goff += consumed_sz;
  return consume_frag;
}

/* fd_snapin_in_update gets called periodically synchronize flow control
   credits back to the stream producer.  Also updates link in metrics. */

static void
fd_snapin_in_update( fd_snapin_in_t * in ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( in->fseq[0] ) = in->seq;
  FD_VOLATILE( in->fseq[1] ) = in->goff;
  FD_COMPILER_MFENCE();

  ulong volatile * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->idx );

  uint * accum = in->accum;
  ulong a0 = accum[0]; ulong a1 = accum[1]; ulong a2 = accum[2];
  ulong a3 = accum[3]; ulong a4 = accum[4]; ulong a5 = accum[5];
  FD_COMPILER_MFENCE();
  metrics[0] += a0;    metrics[1] += a1;    metrics[2] += a2;
  metrics[3] += a3;    metrics[4] += a4;    metrics[5] += a5;
  FD_COMPILER_MFENCE();
  accum[0] = 0U;       accum[1] = 0U;       accum[2] = 0U;
  accum[3] = 0U;       accum[4] = 0U;       accum[5] = 0U;
}

// __attribute__((noreturn)) static void
// fd_snapin_shutdown( void ) {
//   FD_MGAUGE_SET( TILE, STATUS, 2UL );
//   /* FIXME set final sequence number */
//   FD_COMPILER_MFENCE();
//   FD_LOG_INFO(( "Finished parsing snapshot" ));

//   for(;;) pause();
// }

__attribute__((noinline)) static void
fd_snapin_run1(
    fd_snapin_tile_t *         ctx,
    ulong                      in_cnt,
    fd_snapin_in_t *           in,         /* [in_cnt] */
    ulong                      out_cnt,
    fd_frag_meta_t **          out_mcache, /* [out_cnt] */
    ulong *                    out_depth,  /* [out_cnt] */
    ulong *                    out_seq,    /* [out_cnt] */
    ulong                      cons_cnt,
    ushort * restrict          event_map,  /* [1+in_cnt+cons_cnt] */
    ulong *                    cons_out,   /* [cons_cnt] */
    ulong **                   cons_fseq,  /* [cons_cnt] */
    ulong volatile ** restrict cons_slow,  /* [cons_cnt] */
    ulong * restrict           cons_seq,   /* [cons_cnt] */
    long                       lazy,
    fd_rng_t *                 rng
) {
  /* in frag stream state */
  ulong in_seq;

  /* out flow control state */
  ulong cr_avail;

  /* housekeeping state */
  ulong event_cnt;
  ulong event_seq;
  ulong async_min;

  /* performance metrics */
  ulong metric_in_backp;
  ulong metric_backp_cnt;
  ulong metric_regime_ticks[9];

  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* in frag stream init */

  in_seq = 0UL; /* First in to poll */

  ulong min_in_depth = (ulong)LONG_MAX;
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    fd_snapin_in_t * this_in = &in[ in_idx ];
    ulong depth = fd_mcache_depth( this_in->mcache->f );
    min_in_depth = fd_ulong_min( min_in_depth, depth );
  }

  FD_TEST( in_cnt==1 );
  // ulong const volatile * restrict shutdown_signal = fd_mcache_seq_laddr_const( in[0].mcache->f ) + 3;

  /* out frag stream init */

  cr_avail = 0UL;

  ulong const burst = BURST;

  ulong cr_max = fd_ulong_if( !out_cnt, 128UL, ULONG_MAX );

  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
    if( FD_UNLIKELY( !out_mcache[ out_idx ] ) ) FD_LOG_ERR(( "NULL out_mcache[%lu]", out_idx ));

    out_depth[ out_idx ] = fd_mcache_depth( out_mcache[ out_idx ] );
    out_seq[ out_idx ] = 0UL;

    cr_max = fd_ulong_min( cr_max, out_depth[ out_idx ] );
  }

  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    if( FD_UNLIKELY( !cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
    cons_slow[ cons_idx ] = (ulong*)(fd_metrics_link_out( fd_metrics_base_tl, cons_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF);
    cons_seq [ cons_idx ] = fd_fseq_query( cons_fseq[ cons_idx ] );
  }

  ulong * out_sync = fd_mcache_seq_laddr( out_mcache[0] );

  /* housekeeping init */

  // if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
  lazy = 1e3L;
  FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

  /* Initial event sequence */

  event_cnt = in_cnt + 1UL + cons_cnt;
  event_seq = 0UL;
  event_map[ event_seq++ ] = (ushort)cons_cnt;
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    event_map[ event_seq++ ] = (ushort)(in_idx+cons_cnt+1UL);
  }
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    event_map[ event_seq++ ] = (ushort)cons_idx;
  }
  event_seq = 0UL;

  async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)lazy, event_cnt ));

  FD_LOG_INFO(( "Running snapshot parser" ));
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    ulong housekeeping_ticks = 0UL;
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      if( FD_LIKELY( event_idx<cons_cnt ) ) { /* cons fctl for cons cons_idx */

        /* Receive flow control credits. */
        ulong cons_idx = event_idx;
        cons_seq[ cons_idx ] = fd_fseq_query( cons_fseq[ cons_idx ] );

      } else if( FD_LIKELY( event_idx>cons_cnt ) ) { /* in fctl for in in_idx */

        /* Send flow control credits and drain flow control diagnostics. */
        ulong in_idx = event_idx - cons_cnt - 1UL;
        // FD_LOG_WARNING(("snapin: updating flow control credits!"));
        fd_snapin_in_update( &in[ in_idx ] );

        /* Input tile finished? */
        // ulong const in_seq_max = FD_VOLATILE_CONST( *shutdown_signal );
        // FD_LOG_WARNING(("snapin: in_seq_max is %lu", in_seq_max));
        // if( FD_UNLIKELY( in_seq_max == in[ 0 ].seq ) ) {
        //   fd_snapin_shutdown();
        // }

      } else { /* event_idx==cons_cnt, housekeeping event */

        /* Send synchronization info */
        FD_COMPILER_MFENCE();
        FD_VOLATILE( out_sync[0] ) = ctx->out_seq;
        FD_VOLATILE( out_sync[1] ) = ctx->out_cnt;
        FD_COMPILER_MFENCE();

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( TILE, HEARTBEAT,                 (ulong)now );
        FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metric_in_backp );
        FD_MCNT_INC  ( TILE, BACKPRESSURE_COUNT,        metric_backp_cnt );
        FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metric_regime_ticks );
        metrics_write( ctx );
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive flow control credits */
        if( FD_LIKELY( cr_avail<cr_max ) ) {
          ulong slowest_cons = ULONG_MAX;
          cr_avail = cr_max;
          for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
            ulong cons_cr_avail = (ulong)fd_long_max( (long)cr_max-fd_long_max( fd_seq_diff( out_seq[ cons_out[ cons_idx ] ], cons_seq[ cons_idx ] ), 0L ), 0L );
            slowest_cons = fd_ulong_if( cons_cr_avail<cr_avail, cons_idx, slowest_cons );
            cr_avail     = fd_ulong_min( cons_cr_avail, cr_avail );
          }
          ctx->out_seq_max = ctx->out_seq + cr_avail;

          if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
            FD_COMPILER_MFENCE();
            (*cons_slow[ slowest_cons ]) += metric_in_backp;
            FD_COMPILER_MFENCE();
          }
        }

        during_housekeeping( ctx );

      }

      /* Select which event to do next (randomized round robin) and
         reload the housekeeping timer. */

      event_seq++;
      if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
        event_seq = 0UL;

        ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        ushort map_tmp        = event_map[ swap_idx ];
        event_map[ swap_idx ] = event_map[ 0        ];
        event_map[ 0        ] = map_tmp;

        if( FD_LIKELY( in_cnt>1UL ) ) {
          swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)in_cnt );
          fd_snapin_in_t in_tmp;
          in_tmp         = in[ swap_idx ];
          in[ swap_idx ] = in[ 0        ];
          in[ 0        ] = in_tmp;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      long next = fd_tickcount();
      housekeeping_ticks = (ulong)(next - now);
      now = next;
    }

    /* Check if we are backpressured. */

    if( FD_UNLIKELY( cr_avail<burst ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
      continue;
    }
    metric_in_backp = 0UL;

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) {
      metric_regime_ticks[0] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[3] += (ulong)(next - now);
      now = next;
      continue;
    }

    ulong prefrag_ticks = 0UL;

    fd_snapin_in_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */

    ulong                         this_in_seq   = this_in->seq;
    fd_stream_frag_meta_t const * this_in_mline = this_in->mline;

    ulong seq_found = fd_frag_meta_seq_query( this_in_mline->f );

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) {
      ulong * housekeeping_regime = &metric_regime_ticks[0];
      ulong * prefrag_regime = &metric_regime_ticks[3];
      ulong * finish_regime = &metric_regime_ticks[6];
      if( FD_UNLIKELY( diff<0L ) ) {
        this_in->seq = seq_found;
        housekeeping_regime = &metric_regime_ticks[1];
        prefrag_regime = &metric_regime_ticks[4];
        finish_regime = &metric_regime_ticks[7];
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ]++;
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] += (uint)(-diff);
      }

      /* Don't bother with spin as polling multiple locations */
      *housekeeping_regime += housekeeping_ticks;
      *prefrag_regime += prefrag_ticks;
      long next = fd_tickcount();
      *finish_regime += (ulong)(next - now);
      now = next;
      continue;
    }

    FD_COMPILER_MFENCE();
    fd_stream_frag_meta_t meta = FD_VOLATILE_CONST( *this_in_mline );
    ulong sz = 0U;
    int consumed_frag = on_stream_frag( ctx, this_in, &meta, &sz );

    this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ] += (uint)sz;

    if( FD_LIKELY( consumed_frag ) ) {

      ulong seq_test = fd_frag_meta_seq_query( this_in_mline->f );
      if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) {
        FD_LOG_ERR(( "Overrun while reading from input %lu", in_seq ));
      }

      /* Windup for the next in poll and accumulate diagnostics */

      this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
      this_in->seq   = this_in_seq;
      this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

      this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ]++;

    }

    metric_regime_ticks[1] += housekeeping_ticks;
    metric_regime_ticks[4] += prefrag_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[7] += (ulong)(next - now);
    now = next;
  }
}

static void
fd_snapin_run( fd_topo_t *      topo,
               fd_topo_tile_t * tile ) {
  fd_stream_frag_meta_t * in_mcache[ LINK_IN_MAX ];
  ulong *                 in_fseq  [ LINK_IN_MAX ];
  fd_memset(in_fseq, 0, sizeof(ulong *)*LINK_IN_MAX );

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = fd_type_pun( topo->links[ tile->in_link_id[ i ] ].mcache );
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }
  FD_TEST( polled_in_cnt<=LINK_IN_MAX );

  fd_frag_meta_t * out_mcache[ tile->out_cnt ];
  ulong            out_depth [ tile->out_cnt ];
  ulong            out_seq   [ tile->out_cnt ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    FD_TEST( out_mcache[ i ] );
    out_depth [ i ] = fd_mcache_depth( out_mcache[ i ] );
    out_seq   [ i ] = 0UL;
  }

  ulong   reliable_cons_cnt = 0UL;
  ulong   cons_out[ FD_TOPO_MAX_LINKS ];
  ulong * cons_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out[ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          reliable_cons_cnt++;
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  fd_snapin_in_t polled_in[ polled_in_cnt ];
  for( ulong i=0UL; i<polled_in_cnt; i++ ) {
    fd_snapin_in_t * this_in = &polled_in[ i ];

    this_in->mcache = in_mcache[ i ];
    this_in->fseq   = in_fseq  [ i ];

    ulong depth    = fd_mcache_depth( this_in->mcache->f );
    if( FD_UNLIKELY( depth > UINT_MAX ) ) FD_LOG_ERR(( "in_mcache[%lu] too deep", i ));
    this_in->depth = (uint)depth;
    this_in->idx   = (uint)i;
    this_in->seq   = 0UL;
    this_in->goff  = 0UL;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

    this_in->accum[0] = 0U; this_in->accum[1] = 0U; this_in->accum[2] = 0U;
    this_in->accum[3] = 0U; this_in->accum[4] = 0U; this_in->accum[5] = 0U;
  }

  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ushort           event_map[ 1+reliable_cons_cnt ];
  ulong volatile * cons_slow[   reliable_cons_cnt ];
  ulong            cons_seq [   reliable_cons_cnt ];
  fd_snapin_run1( ctx, polled_in_cnt, polled_in, reliable_cons_cnt, out_mcache, out_depth, out_seq, reliable_cons_cnt, event_map, cons_out, cons_fseq, cons_slow, cons_seq, (ulong)10e3, rng );
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
