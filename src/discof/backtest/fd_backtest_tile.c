#include <errno.h>
#include <fcntl.h>

#include "../../ballet/reedsol/fd_reedsol.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../disco/fd_disco.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/fd_discof.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../util/pod/fd_pod_format.h"

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

  fd_wksp_t *            replay_in_mem;
  ulong                  replay_in_chunk0;
  ulong                  replay_in_wmark;

  fd_wksp_t *            replay_out_mem;
  ulong                  replay_out_chunk0;
  ulong                  replay_out_wmark;
  ulong                  replay_out_chunk;

  fd_replay_notif_msg_t  replay_notification;

  ulong                  root_out_out_idx;

  ulong                  playback_started;
  ulong                  end_slot;
  ulong                  start_slot;

  ulong *                published_wmark; /* same as the one in replay tile */
  fd_alloc_t *           alloc;
  long                   replay_time;
  ulong                  slot_cnt;

  fd_store_t *           store;
  fd_tower_t *           tower;
  fd_shred_t const *     curr;
  fd_hash_t              prev_mr;

  /* is_ready is used to determine if the backtest tile should send
     more fec sets to the replay tile. is_ready==1 if more fec sets
     should be sent; it gets set to 0 while waiting for an end of slot
     notification from the replay tile. When a slot notification is
     received, is_ready is set to 1 again. */
  int is_ready;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( ctx_t ),         sizeof( ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()         );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(),         fd_tower_footprint()         );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_map_align(), fd_bank_hash_map_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 2UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static fd_shred_t const *
rocksdb_get_shred( ctx_t * ctx,
                   ulong * out_sz ) {
  if( ctx->rocksdb_curr_idx==ctx->rocksdb_end_idx ) {
    if( FD_UNLIKELY( fd_rocksdb_root_iter_next( &ctx->rocksdb_root_iter, &ctx->rocksdb_slot_meta ) ) ) return NULL;
    if( FD_UNLIKELY( fd_rocksdb_get_meta( &ctx->rocksdb, ctx->rocksdb_slot_meta.slot, &ctx->rocksdb_slot_meta ) ) ) return NULL;
    ctx->rocksdb_curr_idx = 0;
    ctx->rocksdb_end_idx  = ctx->rocksdb_slot_meta.received;
  }
  ulong slot = ctx->rocksdb_slot_meta.slot;

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
  if( ctx->ingest_mode == FD_BACKTEST_ROCKSDB_INGEST ) {
    /* We want to publish the previous last_replayed_slot, when we have
       finished replaying the current slot. Then we can update the
       last_replayed_slot to the newly executed slot. */
    fd_stem_publish( stem, ctx->root_out_out_idx, ctx->replay_notification.slot_exec.slot, 0UL, 0UL, 0UL, tsorig, tspub );
    ctx->is_ready = 1;

  } else if( ctx->ingest_mode == FD_BACKTEST_SHREDCAP_INGEST ) {
    ulong root = fd_tower_vote( ctx->tower, replayed_slot );
    if( FD_LIKELY( root != FD_SLOT_NULL ) ) {
      fd_stem_publish( stem, ctx->root_out_out_idx, root, 0UL, 0UL, 0UL, tsorig, tspub );
    }
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  void * alloc_shmem       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()         );
  void * tower_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(),         fd_tower_footprint()         );
  void * bank_hash_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_map_align(), fd_bank_hash_map_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

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

  /* Tower */
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem ) );
  if( FD_UNLIKELY( !ctx->tower ) ) {
    FD_LOG_ERR( ( "fd_tower_join failed" ) );
  }

  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ REPLAY_IN_IDX ] ];
  ctx->replay_in_mem              = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0           = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark            = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "repair_repla", 0 );
  FD_TEST( out_idx!=ULONG_MAX );
  fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];
  ctx->replay_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, link->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark( ctx->replay_out_mem, link->dcache, link->mtu );
  ctx->replay_out_chunk  = ctx->replay_out_chunk0;

  ctx->root_out_out_idx = fd_topo_find_tile_out_link( topo, tile, "root_out", 0 );
  FD_TEST( ctx->root_out_out_idx!= ULONG_MAX );

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
  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  /* Setup the wmark fseq shared with replay tile */
  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );

  ctx->replay_time = LONG_MAX;
  ctx->slot_cnt    = 0UL;

  ctx->curr = NULL;
  ctx->prev_mr = (fd_hash_t){0};

  ctx->is_ready = 1;

  FD_LOG_NOTICE(( "Finished unprivileged init" ));
}

fd_hash_t
query_mr( fd_shred_t const * shred ) {
  fd_bmtree_node_t bmtree_root;
  uchar bmtree_mem[fd_bmtree_commit_footprint( 10UL )]__attribute__( ( aligned( FD_BMTREE_COMMIT_ALIGN ) ) );
  fd_shred_merkle_root( shred, bmtree_mem, &bmtree_root );
  fd_hash_t mr;
  memcpy( &mr, &bmtree_root, sizeof(fd_bmtree_node_t) );
  return mr;
}

static void
after_credit_rocksdb( ctx_t *             ctx,
                      fd_stem_context_t * stem,
                      int *               opt_poll_in FD_PARAM_UNUSED,
                      int *               charge_busy ) {

  if( FD_UNLIKELY( !ctx->playback_started ) ) {
    ulong wmark = fd_fseq_query( ctx->published_wmark );
    if( wmark==ULONG_MAX ) return;
    if( ctx->start_slot==ULONG_MAX ) ctx->start_slot=wmark;
    if( wmark!=ctx->replay_notification.slot_exec.slot ) return;
    if (ctx->replay_time==LONG_MAX) ctx->replay_time = -fd_log_wallclock();
    ctx->playback_started = 1;

    fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
    if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta ) ) ) {
      FD_LOG_CRIT(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
    }
    ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);
  }

  /* If the slot we just sent to the replay tile has not finished
     replaying, then we will block until it's done replaying and a
     notification is received from the replay tile. */

  if( ctx->is_ready==0 ) {
    return;
  }

  ulong sz;
  fd_shred_t const * prev = NULL;
  fd_shred_t const * curr = ctx->curr ? ctx->curr : rocksdb_get_shred( ctx, &sz );
  if( FD_UNLIKELY ( !curr ) ) return; /* finished replay */

  fd_hash_t mr = query_mr( curr );
  fd_store_exacq ( ctx->store ); /* FIXME shacq after store changes */
  fd_store_insert( ctx->store, 0, &mr );
  fd_store_exrel ( ctx->store ); /* FIXME */
  while( FD_LIKELY( 1 ) ) {
    ulong            sz  = fd_shred_payload_sz( curr );
    fd_store_fec_t * fec = fd_store_query( ctx->store, &mr );
    FD_TEST( fec );
    fd_store_exacq( ctx->store ); /* FIXME shacq after store changes */
    memcpy( fec->data + fec->data_sz, fd_shred_data_payload( curr ), sz );
    fec->data_sz += sz;
    fd_store_exrel( ctx->store ); /* FIXME */
    // FD_LOG_WARNING(( "inserting shred %lu %u %lu %lu", curr->slot, curr->idx, sz, fec->data_sz ));
    prev = curr;
    curr = rocksdb_get_shred( ctx, &sz );
    if( FD_UNLIKELY( !curr || curr->fec_set_idx != prev->fec_set_idx || curr->slot != prev->slot ) ) break;
  }
  FD_TEST( prev );

  /* Link the merkle roots here; as this step usually occurs in repair */
  fd_store_exacq ( ctx->store );
  fd_store_link( ctx->store, &mr, &ctx->prev_mr );
  fd_store_exrel( ctx->store );

  /* Instead of using the shred->chained_mr, there's a known issue with
     fd where it might produce a bad chained mr for the first FEC set in
     a slot of it's leader window.  So best to just track the previous
     merkle root directly. */

  ctx->prev_mr = mr;

  fd_hash_t cmr;
  memcpy( cmr.uc, (uchar const *)prev + fd_shred_chain_off( prev->variant ), sizeof(fd_hash_t) );
  fd_reasm_fec_t out = {
    .key           = mr,
    .cmr           = cmr,
    .slot          = prev->slot,
    .parent_off    = prev->data.parent_off,
    .fec_set_idx   = prev->fec_set_idx,
    .data_cnt      = (ushort)( prev->idx + 1 - prev->fec_set_idx ),
    .data_complete = !!( prev->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ),
    .slot_complete = !!( prev->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE )
  };
  ulong sig   = out.slot << 32 | out.fec_set_idx;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  memcpy( fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk ), &out, sizeof(fd_reasm_fec_t) );
  fd_stem_publish( stem, REPLAY_OUT_IDX, sig, ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), 0, 0, tspub );
  ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );
  ctx->curr = curr;
  *charge_busy = 1;

  if( out.slot_complete ) {
    ctx->is_ready = 0;
  }

  return; /* yield otherwise it will overrun */
}

static void
shredcap_notify_one_fec( ctx_t * ctx, fd_stem_context_t * stem ) {

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

  ulong off = 0;

  fd_hash_t * merkle_root = (fd_hash_t *)fd_type_pun( slice_buf + off );
  off += sizeof(fd_hash_t);

  fd_store_exacq( ctx->store );
  fd_store_fec_t * fec = fd_store_insert( ctx->store, 0, merkle_root );

  fec->data_sz = fd_ulong_load_1( slice_buf + off );
  off += sizeof(ulong);

  memcpy( fec->data, slice_buf + off, fec->data_sz );
  off += fec->data_sz;
  fd_store_exrel( ctx->store );

  fd_reasm_fec_t * out = (fd_reasm_fec_t *)(slice_buf + off);
  off += sizeof(fd_reasm_fec_t);

  ulong sig   = out->slot << 32 | out->fec_set_idx;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, REPLAY_OUT_IDX, sig, ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), 0, 0, tspub );
  ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );

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
  if( ctx->ingest_mode==FD_BACKTEST_ROCKSDB_INGEST ) {
    after_credit_rocksdb( ctx, stem, opt_poll_in, charge_busy );
    return;
  }

  if( FD_UNLIKELY( !ctx->playback_started ) ) {

    /* Handle bootup. */

    ulong wmark = fd_fseq_query( ctx->published_wmark );
    if( wmark==ULONG_MAX ) return;
    if( ctx->start_slot==ULONG_MAX ) ctx->start_slot=wmark;
    if( wmark!=ctx->replay_notification.slot_exec.slot ) return;

    if( FD_UNLIKELY( ctx->replay_time==LONG_MAX) ) ctx->replay_time = -fd_log_wallclock();
    ctx->playback_started=1;

    switch( ctx->ingest_mode ) {
      case FD_BACKTEST_ROCKSDB_INGEST:
        fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
        if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta ) ) ) {
          FD_LOG_CRIT(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
        }
        ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);
        break;
      case FD_BACKTEST_SHREDCAP_INGEST:
        break;
      default:
        FD_LOG_CRIT(( "Invalid ingest mode: %lu", ctx->ingest_mode ));
    }
  }

  shredcap_notify_one_fec( ctx, stem );
}

static void
during_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig FD_PARAM_UNUSED,
             ulong   chunk,
             ulong   sz,
             ulong   ctl FD_PARAM_UNUSED ) {
  FD_TEST( !in_idx );
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

  fd_frozen_hash_versioned_t versioned[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static( frozen_hash_versioned, versioned, res, vallen, NULL ) ) ||
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
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
