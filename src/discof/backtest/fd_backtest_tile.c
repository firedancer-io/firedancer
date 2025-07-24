#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco.h"
#include "../../disco/stem/fd_stem.h"
#include "../../choreo/tower/fd_tower.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../discof/fd_discof.h"
#include <errno.h>

#define REPLAY_IN_IDX                 (0UL)
#define REPLAY_OUT_IDX                (0UL)

#define FD_ARCHIVER_ROCKSDB_ALLOC_TAG (4UL)

#define FD_BACKTEST_ROCKSDB_INGEST  (0UL)
#define FD_BACKTEST_SHREDCAP_INGEST (1UL)

/* TODO: this should be bounded to the max number of unrooted banks
   that the client can support. Currently there is no bound, so 2048
   is a relatively reasonable bound. */
#define FD_BANK_HASH_MAP_SLOT_CNT (2048UL)

/* This buffer is used to buffer in a slice from the shredcap file. */
static uchar slice_buf[ FD_SLICE_MAX_WITH_HEADERS ];

/* TODO: Make these buffers configurably sized. */
static uchar shred_io_buf[ 4096UL ];
static uchar bank_hash_io_buf[ 4096UL ];

struct fd_bank_hash_map_ele {
  ulong     slot;
  uint      hash;
  fd_hash_t bank_hash;
};
typedef struct fd_bank_hash_map_ele fd_bank_hash_map_ele_t;


#define MAP_NAME        fd_bank_hash_map
#define MAP_T           fd_bank_hash_map_ele_t
#define MAP_KEY         slot
#define MAP_LG_SLOT_CNT 11
#include "../../util/tmpl/fd_map.c"
#undef MAP_NAME
#undef MAP_T
#undef MAP_LG_SLOT_CNT

typedef struct {
  /* Backtest supports ingest from a rocksdb or a shredcap file.*/
  ulong                    ingest_mode;

  /* If the ingest mode is shredcap, then we expect to read from two
     files. The first is a file containing shreds that may be in any
     order. The second is a file that contains bank hashes. */
  fd_io_buffered_istream_t shred_istream;
  fd_io_buffered_istream_t bank_hash_istream;
  int                      shred_fd;
  int                      bank_hash_fd;
  fd_bank_hash_map_ele_t * bank_hash_map;
  ulong                    bank_hash_map_cnt;
  int                      shred_eof;

  /* If the ingest mode is rocksdb, then we expect to read shreds and
     bank hashes from the rocksdb. */
  fd_rocksdb_t           rocksdb;
  rocksdb_iterator_t *   rocksdb_iter;
  fd_rocksdb_root_iter_t rocksdb_root_iter;
  fd_slot_meta_t         rocksdb_slot_meta;
  ulong                  rocksdb_curr_idx;
  ulong                  rocksdb_end_idx;
  ulong                  rocksdb_end_slot;
  uchar *                rocksdb_bank_hash;

  fd_wksp_t *            blockstore_wksp;
  fd_blockstore_t        blockstore_ljoin;
  fd_blockstore_t *      blockstore;

  fd_wksp_t *            replay_in_mem;
  ulong                  replay_in_chunk0;
  ulong                  replay_in_wmark;
  fd_replay_notif_msg_t  replay_notification;

  ulong                  tower_replay_out_idx;

  ulong                  playback_started;
  ulong                  end_slot;
  ulong                  start_slot;

  ulong *                published_wmark; /* same as the one in replay tile */
  fd_alloc_t *           alloc;
  fd_valloc_t            valloc;
  long                   replay_time;
  ulong                  slot_cnt;

  fd_tower_t *           tower;
} ctx_t;

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 2UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static fd_shred_t const *
rocksdb_get_shred( ctx_t * ctx,
                   ulong                           * out_sz ) {
  if( ctx->rocksdb_curr_idx==ctx->rocksdb_end_idx ) {
    if( FD_UNLIKELY( fd_rocksdb_root_iter_next( &ctx->rocksdb_root_iter, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
    if( FD_UNLIKELY( fd_rocksdb_get_meta( &ctx->rocksdb, ctx->rocksdb_slot_meta.slot, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
    ctx->rocksdb_curr_idx = 0;
    ctx->rocksdb_end_idx  = ctx->rocksdb_slot_meta.received;
  }
  ulong slot                = ctx->rocksdb_slot_meta.slot;

  char k[16];
  *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(ctx->rocksdb_curr_idx);
  rocksdb_iter_seek(ctx->rocksdb_iter, (const char *) k, sizeof(k));

  ulong cur_slot, index;
  uchar valid = rocksdb_iter_valid(ctx->rocksdb_iter);

  if (valid) {
    size_t klen = 0;
    const char* key = rocksdb_iter_key(ctx->rocksdb_iter, &klen); // There is no need to free key
    if (klen != 16)  // invalid key
      FD_LOG_ERR(( "rocksdb has invalid key length" ));
    cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
    index = fd_ulong_bswap(*((ulong *) &key[8]));
  }

  if (!valid || cur_slot != slot)
    FD_LOG_ERR(("missing shreds for slot %lu, valid=%u", slot, valid));

  if (index != ctx->rocksdb_curr_idx)
    FD_LOG_ERR(("missing shred %lu at index %lu for slot %lu", ctx->rocksdb_curr_idx, index, slot));

  size_t dlen = 0;
  // Data was first copied from disk into memory to make it available to this API
  const unsigned char *data = (const unsigned char *) rocksdb_iter_value(ctx->rocksdb_iter, &dlen);
  if (data == NULL)
    FD_LOG_ERR(("failed to read shred %lu/%lu", slot, ctx->rocksdb_curr_idx));

  // This just correctly selects from inside the data pointer to the
  // actual data without a memory copy
  fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
  ctx->rocksdb_curr_idx++;

  *out_sz = dlen;
  return shred;
}

static void
notify_tower_root( ctx_t *             ctx,
                   fd_stem_context_t * stem,
                   ulong               tsorig,
                   ulong               tspub ) {
  ulong replayed_slot = ctx->replay_notification.slot_exec.slot;
  ulong root          = fd_tower_vote( ctx->tower, replayed_slot );
  if( FD_LIKELY( root != FD_SLOT_NULL ) ) {
    fd_stem_publish( stem, ctx->tower_replay_out_idx, root, 0UL, 0UL, 0UL, tsorig, tspub );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  void * alloc_shmem       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  void * tower_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  void * bank_hash_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_map_align(), fd_bank_hash_map_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, 4096UL );

  /* Determine the ingest mode */
  if( FD_UNLIKELY( strcmp( tile->archiver.ingest_mode, "rocksdb" )==0 ) ) {
    ctx->ingest_mode = FD_BACKTEST_ROCKSDB_INGEST;
  } else if( FD_UNLIKELY( strcmp( tile->archiver.ingest_mode, "shredcap" )==0 ) ) {
    ctx->ingest_mode = FD_BACKTEST_SHREDCAP_INGEST;
  } else {
    FD_LOG_ERR(( "Invalid ingest mode: %s", tile->archiver.ingest_mode ));
  }

  /* Allocator */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, FD_ARCHIVER_ROCKSDB_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  /* Tower */
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem ) );
  if( FD_UNLIKELY( !ctx->tower ) ) {
    FD_LOG_ERR( ( "fd_tower_join failed" ) );
  }

  ctx->rocksdb_bank_hash = fd_valloc_malloc( ctx->valloc, fd_frozen_hash_versioned_align(), sizeof(fd_frozen_hash_versioned_t) );
  if( FD_UNLIKELY( NULL==ctx->rocksdb_bank_hash ) ) {
    FD_LOG_ERR(( "Failed at allocating memory for rocksdb bank hash" ));
  }

  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ REPLAY_IN_IDX ] ];
  ctx->replay_in_mem              = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0           = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark            = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  ctx->tower_replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "tower_replay", 0 );
  FD_TEST( ctx->tower_replay_out_idx!= ULONG_MAX );

  ctx->playback_started           = 0;
  ctx->end_slot          = tile->archiver.end_slot;
  ctx->start_slot        = ULONG_MAX;
  if( FD_UNLIKELY( 0==ctx->end_slot ) ) FD_LOG_ERR(( "end_slot is required for rocksdb playback" ));

  /* setup for rocksdb ingest */
  if( ctx->ingest_mode==FD_BACKTEST_ROCKSDB_INGEST ) {
    ctx->rocksdb_curr_idx = 0;
    ctx->rocksdb_end_idx  = 0;
    fd_memset( &ctx->rocksdb, 0, sizeof(fd_rocksdb_t) );
    fd_memset( &ctx->rocksdb_slot_meta, 0, sizeof(fd_slot_meta_t) );
    fd_memset( &ctx->rocksdb_root_iter, 0, sizeof(fd_rocksdb_root_iter_t) );
    fd_rocksdb_init( &ctx->rocksdb, tile->archiver.rocksdb_path );
    char * err = NULL;
    ulong rocksdb_end_slot = fd_rocksdb_last_slot( &ctx->rocksdb, &err );
    if( FD_UNLIKELY( err!=NULL ) ) {
      FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", err ));
    }
    if( FD_UNLIKELY( rocksdb_end_slot<ctx->end_slot ) ) {
      FD_LOG_ERR(( "RocksDB only has shreds up to slot=%lu, so it cannot playback to end_slot=%lu",
                   rocksdb_end_slot, ctx->end_slot ));
    }
    ctx->rocksdb_end_slot=rocksdb_end_slot;

  } else if( ctx->ingest_mode==FD_BACKTEST_SHREDCAP_INGEST ) {

    /* Setup file ingest from shredcap file. */
    ctx->shred_fd = open( tile->archiver.shredcap_path, O_RDONLY );
    if( FD_UNLIKELY( ctx->shred_fd==-1 ) ) {
      FD_LOG_ERR(( "Failed at opening shredcap file: %s, error: %s", tile->archiver.shredcap_path, fd_io_strerror( errno ) ));
    }
    fd_io_buffered_istream_init( &ctx->shred_istream, ctx->shred_fd, shred_io_buf, sizeof(shred_io_buf) );
    ctx->shred_eof = 0;

    ctx->bank_hash_fd = open( tile->archiver.bank_hash_path, O_RDONLY );
    if( FD_UNLIKELY( ctx->bank_hash_fd==-1 ) ) {
      FD_LOG_ERR(( "Failed at opening bank hash file: %s, error: %s", tile->archiver.bank_hash_path, fd_io_strerror( errno ) ));
    }
    fd_io_buffered_istream_init( &ctx->bank_hash_istream, ctx->bank_hash_fd, bank_hash_io_buf, sizeof(bank_hash_io_buf) );

    /* Setup bank hash map. We need a map because the execution may
       occur out of order. This means that we need to prefetch the bank
       hashes for several slots at a time. */
    ctx->bank_hash_map = fd_bank_hash_map_join( fd_bank_hash_map_new( bank_hash_map_mem ) );
    if( FD_UNLIKELY( !ctx->bank_hash_map ) ) {
      FD_LOG_CRIT(( "Failed at joining bank hash map" ));
    }
    ctx->bank_hash_map_cnt = 0UL;
  }

  /* Setup the blockstore */
  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;
  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blockstore wksp" ));
  }

  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  fd_buf_shred_pool_reset( ctx->blockstore->shred_pool, 0 );
  FD_TEST( ctx->blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );

  /* Setup the wmark fseq shared with replay tile */
  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );

  ctx->replay_time = LONG_MAX;
  ctx->slot_cnt    = 0UL;

  FD_LOG_NOTICE(("Finished unprivileged init"));
}

FD_FN_UNUSED static void
rocksdb_notify_one_batch( ctx_t * ctx, fd_stem_context_t * stem ) {

  /* Read shreds out until we have assembled a complete batch. When
     reading from rocksdb, we make the assumption that all of the data
     shreds are in order. */
  uint cnt = 0UL;
  while( true ) {
    ulong              sz    = 0UL;
    fd_shred_t const * shred = rocksdb_get_shred( ctx, &sz );
    cnt++;
    if( FD_UNLIKELY( shred==NULL ) ) {
      return;
    }

    fd_blockstore_shred_insert( ctx->blockstore, shred );
    if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
      /* Notify the replay tile after inserting a FEC set */
      ulong sig   = fd_disco_repair_replay_sig( shred->slot, (ushort)(shred->slot - ctx->rocksdb_slot_meta.parent_slot), cnt, slot_complete );
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, REPLAY_OUT_IDX, sig, 0, 0, 0, tspub, tspub );
      break;
    }
  }
}

static void
notify_one_slot( ctx_t * ctx, fd_stem_context_t * stem ) {
  uint entry_batch_start_idx = 0;
  int  slot_complete         = 0;
  while( !slot_complete ) {
    ulong sz                 = 0;
    fd_shred_t const * shred = rocksdb_get_shred( ctx, &sz );
    if( FD_UNLIKELY( shred==NULL ) ) {
      break;
    } else {
      fd_blockstore_shred_insert( ctx->blockstore, shred );
      if( !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE) ) {
        slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
        /* Notify the replay tile after inserting a FEC set */
        FD_LOG_DEBUG(( "%lu:[%u, %u] notifies replay", shred->slot, entry_batch_start_idx, shred->idx ));
        uint  cnt             = shred->idx+1-entry_batch_start_idx;
        entry_batch_start_idx = shred->idx+1;
        ulong sig             = fd_disco_repair_replay_sig( shred->slot, (ushort)(shred->slot - ctx->rocksdb_slot_meta.parent_slot), cnt, slot_complete );
        ulong tspub           = fd_frag_meta_ts_comp( fd_tickcount() );
        fd_stem_publish( stem, REPLAY_OUT_IDX, sig, 0, 0, 0, tspub, tspub );
      }
    }
  }
}

static void
shredcap_notify_one_batch( ctx_t * ctx, fd_stem_context_t * stem ) {

  if( ctx->shred_eof ) {
    return;
  }

  /* First read in the header and do some simple validation. */
  uchar header_buf[ FD_SHREDCAP_SLICE_HEADER_FOOTPRINT ];
  int err = fd_io_buffered_istream_read( &ctx->shred_istream, header_buf, FD_SHREDCAP_SLICE_HEADER_FOOTPRINT );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_NOTICE(( "EOF reached" ));
    ctx->shred_eof = 1;
    return;
  }
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "Failed at reading shredcap slice header: %d", err ));
  }
  fd_shredcap_slice_header_msg_t * header = (fd_shredcap_slice_header_msg_t *)header_buf;
  fd_shredcap_slice_header_validate( header );

  switch( header->version ) {

  case FD_SHREDCAP_SLICE_HEADER_V1: {

  /* Read in the payload. */
  err = fd_io_buffered_istream_read( &ctx->shred_istream, slice_buf, header->payload_sz );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_NOTICE(( "EOF reached" ));
    ctx->shred_eof = 1;
    return;
  }
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "Failed at reading shredcap slice payload: %d", err ));
  }

  /* Read in the trailer and do some simple validation. */
  uchar trailer_buf[ FD_SHREDCAP_SLICE_TRAILER_FOOTPRINT ];
  err = fd_io_buffered_istream_read( &ctx->shred_istream, trailer_buf, FD_SHREDCAP_SLICE_TRAILER_FOOTPRINT );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_NOTICE(( "EOF reached" ));
    ctx->shred_eof = 1;
    return;
  }
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "Failed at reading shredcap slice trailer: %d", err ));
  }
  fd_shredcap_slice_trailer_msg_t * trailer = (fd_shredcap_slice_trailer_msg_t *)trailer_buf;
  if( FD_UNLIKELY( trailer->magic!=FD_SHREDCAP_SLICE_TRAILER_MAGIC ) ) {
    FD_LOG_ERR(( "Invalid magic number in shredcap slice trailer: %lu", trailer->magic ));
  }
  fd_shredcap_slice_trailer_validate( trailer );

  /* At this point, we know that we have a complete slice that was
    most likely written out correctly. Now, we should iterate through
    the slice and insert the shreds into the blockstore. */
  uchar *      shred_buf  = slice_buf;
  ulong        bytes_left = header->payload_sz;
  fd_shred_t * shred      = NULL;
  uint         cnt        = 0UL;
  while( bytes_left>0 ) {
    shred = (fd_shred_t *)shred_buf;
    ulong shred_payload_sz = fd_shred_sz( shred );

    if( FD_UNLIKELY( shred_payload_sz > bytes_left ) ) {
      FD_LOG_ERR(( "Shred payload size %lu is greater than the remaining bytes in the slice %lu", shred_payload_sz, bytes_left ));
    }
    fd_blockstore_shred_insert( ctx->blockstore, shred );
    cnt++;
    bytes_left -= shred_payload_sz;
    shred_buf  += shred_payload_sz;
  }

  if( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
    int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);

    ulong sig   = fd_disco_repair_replay_sig( shred->slot, shred->data.parent_off, cnt, slot_complete );
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, REPLAY_OUT_IDX, sig, 0, 0, 0, tspub, tspub );
  }
  break;

  /* Add more versions here. */
  } default:

  FD_LOG_CRIT(( "Invalid version in shredcap slice header: %lu", header->version ));

  }

}

static void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy FD_PARAM_UNUSED ) {


  if( FD_UNLIKELY( !ctx->playback_started ) ) {

    /* Handle bootup. */

    ulong wmark = fd_fseq_query( ctx->published_wmark );
    if( wmark==ULONG_MAX ) return;
    if( ctx->start_slot==ULONG_MAX ) ctx->start_slot=wmark;
    if( wmark!=ctx->replay_notification.slot_exec.slot ) return;

    if (ctx->replay_time==LONG_MAX) {
      ctx->replay_time = -fd_log_wallclock();
    }

    ctx->playback_started=1;

    switch( ctx->ingest_mode ) {
      case FD_BACKTEST_ROCKSDB_INGEST:
        fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
        if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) {
          FD_LOG_CRIT(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
        }
        ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);
        notify_one_slot( ctx, stem );
        break;
      case FD_BACKTEST_SHREDCAP_INGEST:
        break;
      default:
        FD_LOG_CRIT(( "Invalid ingest mode: %lu", ctx->ingest_mode ));
    }
  }

  /* If the replay tile is not backpressured, we will notify with more
     batches that are ready to be executed. */
  switch( ctx->ingest_mode ) {
    case FD_BACKTEST_ROCKSDB_INGEST:
      // rocksdb_notify_one_batch( ctx, stem );
      break;
    case FD_BACKTEST_SHREDCAP_INGEST:
      shredcap_notify_one_batch( ctx, stem );
      break;
    default:
      FD_LOG_CRIT(( "Invalid ingest mode: %lu", ctx->ingest_mode ));
  }
  return;
}

static void
during_frag( ctx_t * ctx,
             ulong                             in_idx,
             ulong                             seq FD_PARAM_UNUSED,
             ulong                             sig FD_PARAM_UNUSED,
             ulong                             chunk,
             ulong                             sz,
             ulong                             ctl FD_PARAM_UNUSED ) {
  FD_TEST( in_idx==0 );
  FD_TEST( sz==sizeof(fd_replay_notif_msg_t) );
  fd_memcpy( &ctx->replay_notification, fd_chunk_to_laddr( ctx->replay_in_mem, chunk ), sizeof(fd_replay_notif_msg_t) );
}

static void
rocksdb_bank_hash_check( ctx_t * ctx, ulong slot, fd_hash_t * bank_hash ) {
  ulong slot_be = fd_ulong_bswap(slot);

  size_t vallen = 0;
  char * err = NULL;
  char * res = rocksdb_get_cf(
    ctx->rocksdb.db,
    ctx->rocksdb.ro,
    ctx->rocksdb.cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
    (char const *)&slot_be, sizeof(ulong),
    &vallen,
    &err );
  if( FD_UNLIKELY( err || vallen==0 ) ) {
    FD_LOG_ERR(( "Failed at reading bank hash for slot%lu from rocksdb", slot ));
  }
  fd_bincode_decode_ctx_t decode = {
    .data    = res,
    .dataend = res + vallen
  };
  ulong total_sz = 0UL;
  int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

  fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( ctx->rocksdb_bank_hash, &decode );
  if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ||
      FD_UNLIKELY( decode.data!=decode.dataend    ) ||
      FD_UNLIKELY( versioned->discriminant!=fd_frozen_hash_versioned_enum_current ) ) {
    FD_LOG_ERR(( "Failed at decoding bank hash from rocksdb" ));
  }

  if( slot!=ctx->start_slot && ctx->start_slot!=ULONG_MAX ) {
    ctx->slot_cnt++;
    if( FD_LIKELY( !memcmp( bank_hash, &versioned->inner.current.frozen_hash, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_NOTICE(( "Bank hash matches! slot=%lu, hash=%s", slot, FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
    } else {
      /* Do not change this log as it is used in offline replay */
      FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s",
                  slot,
                  FD_BASE58_ENC_32_ALLOCA( versioned->inner.current.frozen_hash.hash ),
                  FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
    }
  }
}

static void
shredcap_bank_hash_check( ctx_t * ctx, ulong slot, fd_hash_t * bank_hash ) {
  /* Query the map to see if we have the bank hash for this slot. If we
     do, then we can compare against the bank hash in the map. After
     we compare the bank hash, we can remove the entry from the map. */

  fd_bank_hash_map_ele_t * ele = fd_bank_hash_map_query( ctx->bank_hash_map, slot, NULL );
  if( FD_UNLIKELY( !ele ) ) {
    while( ctx->bank_hash_map_cnt<FD_BANK_HASH_MAP_SLOT_CNT ) {
      fd_shredcap_bank_hash_msg_t msg[1];
      int err = fd_io_buffered_istream_read( &ctx->bank_hash_istream, msg, FD_SHREDCAP_BANK_HASH_FOOTPRINT );
      if( err==-1 ) { /* fd_io_read returns -1 on EOF */
        break;
      }
      if( FD_UNLIKELY( err!=0 ) ) {
        FD_LOG_CRIT(( "Failed at reading bank hash from shredcap file %d", err ));
      }

      fd_shredcap_bank_hash_msg_validate( msg );

      ele = fd_bank_hash_map_insert( ctx->bank_hash_map, msg->slot );
      if( FD_UNLIKELY( !ele ) ) {
        FD_LOG_CRIT(( "Failed at inserting bank hash into map %lu", msg->slot ));
      }
      fd_memcpy( &ele->bank_hash, &msg->bank_hash, sizeof(fd_hash_t) );
      ctx->bank_hash_map_cnt++;
    }
  }

  ele = fd_bank_hash_map_query( ctx->bank_hash_map, slot, NULL );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_WARNING(( "Bank hash not found for slot=%lu", slot ));
    return;
  }

  if( FD_LIKELY( !memcmp( bank_hash, &ele->bank_hash, sizeof(fd_hash_t) ) ) ) {
    FD_LOG_NOTICE(( "Bank hash matches! slot=%lu, hash=%s", slot, FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
  } else {
    FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s", slot, FD_BASE58_ENC_32_ALLOCA( ele->bank_hash.hash ), FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
  }
  fd_bank_hash_map_remove( ctx->bank_hash_map, ele );
  ctx->bank_hash_map_cnt--;
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx FD_PARAM_UNUSED,
            ulong               seq FD_PARAM_UNUSED,
            ulong               sig FD_PARAM_UNUSED,
            ulong               sz FD_PARAM_UNUSED,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  if( FD_LIKELY( ctx->replay_notification.type==FD_REPLAY_SLOT_TYPE ) ) {
    fd_hash_t * bank_hash = &ctx->replay_notification.slot_exec.bank_hash;
    ulong       slot      = ctx->replay_notification.slot_exec.slot;

    /* Compare bank_hash with what is recorded */
    switch( ctx->ingest_mode ) {
      case FD_BACKTEST_ROCKSDB_INGEST:
        rocksdb_bank_hash_check( ctx, slot, bank_hash );
        notify_one_slot( ctx, stem );
        break;
      case FD_BACKTEST_SHREDCAP_INGEST:
        shredcap_bank_hash_check( ctx, slot, bank_hash );
        break;
      default:
        FD_LOG_CRIT(( "Invalid ingest mode: %lu", ctx->ingest_mode ));
    }

    notify_tower_root( ctx, stem, tsorig, tspub );

    if( FD_UNLIKELY( slot>=ctx->end_slot ) ) {
      ctx->replay_time += fd_log_wallclock();
      double replay_time_s = (double)ctx->replay_time * 1e-9;
      double sec_per_slot  = replay_time_s / (double)ctx->slot_cnt;
      FD_LOG_NOTICE((
            "replay completed - slots: %lu, elapsed: %6.6f s, sec/slot: %6.6f",
            ctx->slot_cnt,
            replay_time_s,
            sec_per_slot ));
      FD_LOG_ERR(( "Backtest playback done." ));
    }
  }
}

#define STEM_BURST                  (2UL)
#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_backtest = {
  .name                     = "back",
  .loose_footprint          = loose_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
