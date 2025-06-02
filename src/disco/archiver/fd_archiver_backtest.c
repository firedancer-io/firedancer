#if FD_HAS_ROCKSDB

#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */
#include "fd_archiver.h"
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../discof/replay/fd_replay_notif.h"

#define REPLAY_IN_IDX                 (0UL)
#define REPLAY_OUT_IDX                (0UL)

#define FD_ARCHIVER_ROCKSDB_ALLOC_TAG (4UL)

struct fd_archiver_backtest_tile_ctx {
  ulong                  use_rocksdb;
  fd_rocksdb_t           rocksdb;
  rocksdb_iterator_t *   rocksdb_iter;
  fd_rocksdb_root_iter_t rocksdb_root_iter;
  fd_slot_meta_t         rocksdb_slot_meta;
  ulong                  rocksdb_curr_idx;
  ulong                  rocksdb_end_idx;
  ulong                  rocksdb_end_slot;
  uchar *                rocksdb_bank_hash;
  ulong                  replay_end_slot;

  fd_wksp_t *            blockstore_wksp;
  fd_blockstore_t        blockstore_ljoin;
  fd_blockstore_t *      blockstore;

  fd_wksp_t *            replay_in_mem;
  ulong                  replay_in_chunk0;
  ulong                  replay_in_wmark;
  fd_replay_notif_msg_t  replay_notification;

  ulong                  playback_started;
  ulong                  playback_end_slot;
  ulong                  playback_start_slot;

  ulong *                published_wmark; /* same as the one in replay tile */
  fd_alloc_t *           alloc;
  fd_valloc_t            valloc;
};
typedef struct fd_archiver_backtest_tile_ctx fd_archiver_backtest_tile_ctx_t;

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 2UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static fd_shred_t const *
rocksdb_get_shred( fd_archiver_backtest_tile_ctx_t * ctx,
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
notify_one_slot( fd_archiver_backtest_tile_ctx_t * ctx,
                 fd_stem_context_t *               stem ) {
  uint entry_batch_start_idx = 0;
  int  slot_complete         = 0;
  while(!slot_complete) {
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
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_backtest_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_backtest_tile_ctx_t), sizeof(fd_archiver_backtest_tile_ctx_t) );
  void * alloc_shmem                   = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, 4096UL );

  /* Allocator */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, FD_ARCHIVER_ROCKSDB_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  ctx->rocksdb_curr_idx = 0;
  ctx->rocksdb_end_idx  = 0;
  fd_memset( &ctx->rocksdb, 0, sizeof(fd_rocksdb_t) );
  fd_memset( &ctx->rocksdb_slot_meta, 0, sizeof(fd_slot_meta_t) );
  fd_memset( &ctx->rocksdb_root_iter, 0, sizeof(fd_rocksdb_root_iter_t) );
  fd_rocksdb_init( &ctx->rocksdb, tile->archiver.archiver_path );

  ctx->rocksdb_bank_hash = fd_valloc_malloc( ctx->valloc, fd_frozen_hash_versioned_align(), sizeof(fd_frozen_hash_versioned_t) );
  if( FD_UNLIKELY( NULL==ctx->rocksdb_bank_hash ) ) {
    FD_LOG_ERR(( "Failed at allocating memory for rocksdb bank hash" ));
  }

  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ REPLAY_IN_IDX ] ];
  ctx->replay_in_mem              = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0           = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark            = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  ctx->playback_started           = 0;
  ctx->playback_end_slot          = tile->archiver.end_slot;
  ctx->playback_start_slot        = ULONG_MAX;
  if( FD_UNLIKELY( 0==ctx->playback_end_slot ) ) FD_LOG_ERR(( "end_slot is required for rocksdb playback" ));

  char * err = NULL;
  ulong rocksdb_end_slot = fd_rocksdb_last_slot( &ctx->rocksdb, &err );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", err ));
  }
  if( FD_UNLIKELY( rocksdb_end_slot<ctx->playback_end_slot ) ) {
    FD_LOG_ERR(( "RocksDB only has shreds up to slot=%lu, so it cannot playback to end_slot=%lu",
                 rocksdb_end_slot, ctx->playback_end_slot ));
  }
  ctx->rocksdb_end_slot=rocksdb_end_slot;

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

  FD_LOG_WARNING(( "Rocksdb tile finishes initialization" ));
}

static void
after_credit( fd_archiver_backtest_tile_ctx_t * ctx,
              fd_stem_context_t *               stem,
              int *                             opt_poll_in FD_PARAM_UNUSED,
              int *                             charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->playback_started ) ) {
    ulong wmark = fd_fseq_query( ctx->published_wmark );
    if( wmark==ULONG_MAX ) return;
    if( ctx->playback_start_slot==ULONG_MAX ) ctx->playback_start_slot=wmark;
    if( wmark!=ctx->replay_notification.slot_exec.slot ) return;

    ctx->playback_started=1;
    fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
    if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta, ctx->valloc ) ) )
        FD_LOG_ERR(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));

    fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
    if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta, ctx->valloc ) ) )
        FD_LOG_ERR(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
    ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

    notify_one_slot( ctx, stem );
  }
}

static void
during_frag( fd_archiver_backtest_tile_ctx_t * ctx,
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
after_frag( fd_archiver_backtest_tile_ctx_t * ctx,
            ulong                             in_idx FD_PARAM_UNUSED,
            ulong                             seq FD_PARAM_UNUSED,
            ulong                             sig FD_PARAM_UNUSED,
            ulong                             sz FD_PARAM_UNUSED,
            ulong                             tsorig FD_PARAM_UNUSED,
            ulong                             tspub FD_PARAM_UNUSED,
            fd_stem_context_t *               stem ) {
  if( FD_LIKELY( ctx->replay_notification.type==FD_REPLAY_SLOT_TYPE ) ) {
    ulong slot            = ctx->replay_notification.slot_exec.slot;
    ulong slot_be         = fd_ulong_bswap(slot);
    fd_hash_t * bank_hash = &ctx->replay_notification.slot_exec.bank_hash;

    /* Compare bank_hash with the record in rocksdb */
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

    if( slot!=ctx->playback_start_slot && ctx->playback_start_slot!=ULONG_MAX ) {
      if( FD_LIKELY( !memcmp( bank_hash, &versioned->inner.current.frozen_hash, sizeof(fd_hash_t) ) ) ) {
        FD_LOG_WARNING(( "Bank hash matches! slot=%lu, hash=%s", slot, FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
      } else {
        FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s",
                    slot,
                    FD_BASE58_ENC_32_ALLOCA( versioned->inner.current.frozen_hash.hash ),
                    FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
      }
    }
    notify_one_slot( ctx, stem );

    if( FD_UNLIKELY( slot>=ctx->playback_end_slot ) ) FD_LOG_ERR(( "Rocksdb playback done." ));
  }
}

#define STEM_BURST                  (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_backtest_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_backtest_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_backtest = {
  .name                     = "btest",
  .loose_footprint          = loose_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#else /* RocksDB not supported */

#include "../topo/fd_topo.h"

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
  FD_LOG_ERR(( "backtest functionality is unavailable: Build does not include RocksDB support.\n"
               "To fix, run ./deps.sh +dev and do a clean rebuild." ));
}

fd_topo_run_tile_t fd_tile_archiver_backtest = {
  .name              = "btest",
  .unprivileged_init = unprivileged_init,
};

#endif /* FD_HAS_ROCKSDB */
