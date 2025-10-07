#include "../backtest/fd_backtest_rocksdb.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../util/pod/fd_pod.h"

/* This tile looks awfully similar to backtest, maybe we could roll it
   into backtest and have an extra option to equivocate. */


#define SHRED_BUFFER_LEN (1048576UL)
#define BANK_HASH_BUFFER_LEN (4096UL)

#define IN_KIND_REPLAY (0)
#define IN_KIND_GENESI (2)

struct fd_eqvoct_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_eqvoct_in fd_eqvoct_in_t;

struct fd_eqvoct_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_eqvoct_out fd_eqvoct_out_t;

struct fd_eqvoct_tile {
  int initialized;

  fd_backtest_rocksdb_t * rocksdb;

  ulong prev_slot;
  ulong prev_fec_set_idx;

  ulong chained_prev_slot;
  ulong chained_prev_fec_set_idx;

  ulong start_slot;
  ulong end_slot;

  ulong reading_slot_cnt;
  ulong reading_slot;
  ulong reading_shred_idx;
  ulong reading_shred_cnt;

  ulong idle_cnt;

  long  replay_time;
  ulong slot_cnt;

  fd_store_t * store;

  int in_kind[ 16UL ];
  fd_eqvoct_in_t in[ 16UL ];

  fd_eqvoct_out_t shred_out[ 1 ];

  ulong shreds_idx;
  ulong shreds_cnt;
  uchar shreds[ SHRED_BUFFER_LEN ][ FD_SHRED_MAX_SZ ];

  ulong bank_hash_idx;
  ulong bank_hash_cnt;
  uchar bank_hashes[ BANK_HASH_BUFFER_LEN ][ 32UL ];
};

typedef struct fd_eqvoct_tile fd_eqvoct_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_eqvoct_tile_t),    sizeof(fd_eqvoct_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_backtest_rocksdb_align(), fd_backtest_rocksdb_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
before_credit( fd_eqvoct_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  if( FD_UNLIKELY( !ctx->initialized ) ) return;

  ctx->idle_cnt++;
  if( FD_UNLIKELY( ctx->idle_cnt<=1UL ) ) return; /* publishing fragments in after credit takes priority */
  if( FD_UNLIKELY( ctx->reading_slot>ctx->end_slot ) ) return; /* finished iterating */
  if( FD_UNLIKELY( ctx->shreds_cnt==SHRED_BUFFER_LEN ) ) return; /* out of space */
  if( FD_UNLIKELY( *stem->min_cr_avail<128UL ) ) return; /* reserve some credits so replay can always publish back */
  if( FD_UNLIKELY( ctx->reading_slot_cnt-ctx->slot_cnt>=33UL ) ) return; /* too far ahead of replay */

  *charge_busy = 1;

  if( FD_UNLIKELY( ctx->reading_shred_cnt==ctx->reading_shred_idx ) ) {
    if( FD_UNLIKELY( ctx->bank_hash_cnt==BANK_HASH_BUFFER_LEN ) ) return; /* out of space */

    int success = fd_backtest_rocksdb_next_root_slot( ctx->rocksdb, &ctx->reading_slot, &ctx->reading_shred_cnt );
    if( FD_UNLIKELY( !success ) ) ctx->reading_slot = ctx->end_slot+1UL; /* no more shreds, mark finished */
    if( FD_UNLIKELY( ctx->reading_slot>ctx->end_slot ) ) return; /* finished iterating */

    ctx->reading_slot_cnt++;
    ctx->reading_shred_idx = 0UL;
    uchar const * bank_hash = fd_backtest_rocksdb_bank_hash( ctx->rocksdb, ctx->reading_slot );
    fd_memcpy( ctx->bank_hashes[ (ctx->bank_hash_idx+ctx->bank_hash_cnt)%BANK_HASH_BUFFER_LEN ], bank_hash, 32UL );
    ctx->bank_hash_cnt++;
  }

  void const * shred = fd_backtest_rocksdb_shred( ctx->rocksdb, ctx->reading_slot, ctx->reading_shred_idx );
  fd_memcpy( ctx->shreds[ (ctx->shreds_idx+ctx->shreds_cnt)%SHRED_BUFFER_LEN ], shred, fd_shred_sz( (fd_shred_t const *)shred ) );

  ctx->reading_shred_idx++;
  ctx->shreds_cnt++;
}

static int
should_equivocate( void ) {
  /* lazy way to get randomness & can only equivocate on the slot boundary */
  return fd_tickcount() % 100 < 30 ;
}

static fd_hash_t
equivocate_fec( fd_eqvoct_tile_t * ctx, fd_shred_t const * shred, uchar * hdr_buf ) {
  /* Copy this fec and zero out the payload */
  fd_hash_t mr1 = { .ul[0] = shred->slot, .ul[1] = shred->fec_set_idx, .ul[2] = 1 };
  fd_store_shacq ( ctx->store );
  fd_store_insert( ctx->store, 0, &mr1 );
  fd_store_shrel ( ctx->store );

  fd_store_fec_t * fec1 = fd_store_query( ctx->store, &mr1 );
  FD_TEST( fec1 );
  fd_store_exacq( ctx->store );
  fd_memset( fec1->data, 0, fd_shred_payload_sz( shred ) );
  fec1->data_sz += fd_shred_payload_sz( shred );
  fd_store_exrel( ctx->store );

  memcpy( hdr_buf, shred, FD_SHRED_DATA_HEADER_SZ );
  fd_shred_t * hdr = (fd_shred_t *)hdr_buf;
  hdr->data.flags |= FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

  return mr1;
}

static void
after_credit( fd_eqvoct_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  int process = ctx->shreds_cnt>=2UL || (ctx->reading_slot>ctx->end_slot && ctx->shreds_cnt );
  if( FD_UNLIKELY( !process ) ) {
    return; /* need to buffer two in ordinary processing for completes fec lookahead */
  }
  if( FD_UNLIKELY( !fd_store_root( ctx->store ) ) ) return; /* todo: hacky, remove, replay initializes this and asserts otherwise */

  *charge_busy = 1;
  ctx->idle_cnt = 0UL;

  fd_shred_t const * shred = (fd_shred_t const *)ctx->shreds[ ctx->shreds_idx ];
  fd_shred_t const * next_shred = (fd_shred_t const *)ctx->shreds[ (ctx->shreds_idx+1UL)%SHRED_BUFFER_LEN ];

  int completes_slot = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  int completes_fec_set = completes_slot || next_shred->slot!=shred->slot || next_shred->fec_set_idx!=shred->fec_set_idx;

  /* FEC sets from the backtest tile will have their merkle root and
     chained merkle root overwritten with their slot numbers and fec
     set index. This is done in order to preserve behavior for older
     ledgers which may not have merkle roots or chained merkle roots. */
  fd_hash_t mr = { .ul[0] = shred->slot, .ul[1] = shred->fec_set_idx };
  if( FD_UNLIKELY( ctx->prev_slot==ULONG_MAX || shred->slot!=ctx->prev_slot || shred->fec_set_idx!=ctx->prev_fec_set_idx ) ) {
    fd_store_shacq ( ctx->store );
    fd_store_insert( ctx->store, 0, &mr );
    fd_store_shrel ( ctx->store );
  }

  fd_store_fec_t * fec = fd_store_query( ctx->store, &mr );
  FD_TEST( fec );
  fd_store_exacq( ctx->store ); /* FIXME shacq after store changes */
  fd_memcpy( fec->data+fec->data_sz, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );
  fec->data_sz += fd_shred_payload_sz( shred );
  fd_store_exrel( ctx->store ); /* FIXME */

  ctx->shreds_idx = (ctx->shreds_idx+1UL)%SHRED_BUFFER_LEN;
  ctx->shreds_cnt--;

  ctx->prev_slot = shred->slot;
  ctx->prev_fec_set_idx = shred->fec_set_idx;

  if( FD_LIKELY( !completes_fec_set ) ) return;

  fd_hash_t cmr = {0};
  if( FD_UNLIKELY( ctx->chained_prev_slot==ULONG_MAX ) ) {
    cmr.ul[ 0 ] = FD_RUNTIME_INITIAL_BLOCK_ID;
  } else {
    cmr.ul[ 0 ] = ctx->chained_prev_slot;
    cmr.ul[ 1 ] = ctx->chained_prev_fec_set_idx;
  }

  ctx->chained_prev_slot = shred->slot;
  ctx->chained_prev_fec_set_idx = shred->fec_set_idx;
  //FD_LOG_INFO(("FEC set complete: slot: %lu, fec_set_idx: %u, batch_complete: %d, slot_complete: %d", shred->slot, shred->fec_set_idx, shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE, shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE));

  /* Complete FEC set, we can equivocate. Start by equivocating on the slot boundary */

  int     is_leader = 0;
  if( FD_UNLIKELY( shred->fec_set_idx == 0 && shred->slot > 1 && should_equivocate() ) ) {
    uchar hdr_buf[ FD_SHRED_DATA_HEADER_SZ ];
    fd_hash_t mr1 = equivocate_fec( ctx, shred, hdr_buf );
    FD_LOG_WARNING(( "Equivocating slot %lu, fec_set_idx %u (new slot_complete), new mr %s", shred->slot, shred->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &mr1 ) ));

    uchar * out_buf   = fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
    memcpy( out_buf, hdr_buf, FD_SHRED_DATA_HEADER_SZ );
    memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ, &mr1, sizeof(fd_hash_t) );
    memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t), &cmr, sizeof(fd_hash_t) );
    memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t), &is_leader, sizeof(int) );
    ulong fec_complete_sz = FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int);

    fd_stem_publish( stem, ctx->shred_out->idx, ULONG_MAX, ctx->shred_out->chunk, fec_complete_sz, 0, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, fec_complete_sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
  }

  /* We need to simulate the FEC set completion message that is sent out
     of the shred tile.  This involves copying the data shred header and
     appending the merkle root and chained merkle root. */
  FD_LOG_WARNING(( "Correct FEC slot %lu, fec_set_idx %u, mr %s", shred->slot, shred->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &mr ) ));
  uchar * out_buf = fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
  memcpy( out_buf, shred, FD_SHRED_DATA_HEADER_SZ );
  memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ, &mr, sizeof(fd_hash_t) );
  memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t), &cmr, sizeof(fd_hash_t) );
  memcpy( out_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t), &is_leader, sizeof(int) );
  ulong fec_complete_sz = FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int);

  fd_stem_publish( stem, ctx->shred_out->idx, ULONG_MAX, ctx->shred_out->chunk, fec_complete_sz, 0, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, fec_complete_sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
}

static inline int
returnable_frag( fd_eqvoct_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_GENESI: {
      ctx->initialized = 1;
      ctx->reading_slot = 0UL;
      ctx->start_slot  = 0UL;
      ctx->replay_time = -fd_log_wallclock();
      fd_backtest_rocksdb_init( ctx->rocksdb, 0UL );
      break;
    }
    case IN_KIND_REPLAY: {
      if( FD_UNLIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED ) ) return 0;
      if( FD_UNLIKELY( !ctx->initialized ) ) return 1;

      fd_replay_slot_completed_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( msg->slot==ctx->start_slot ) ) return 0;

      if( FD_LIKELY( !memcmp( msg->bank_hash.uc, ctx->bank_hashes[ ctx->bank_hash_idx ], 32UL ) ) ) {
        FD_LOG_NOTICE(( "Bank hash matches! slot=%lu, hash=%s", msg->slot, FD_BASE58_ENC_32_ALLOCA( msg->bank_hash.uc ) ));
      } else {
        /* Do not change this log as it is used in offline replay */
        FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%s, got=%s", msg->slot, FD_BASE58_ENC_32_ALLOCA( ctx->bank_hashes[ ctx->bank_hash_idx ] ), FD_BASE58_ENC_32_ALLOCA( msg->bank_hash.uc ) ));
      }
      ctx->bank_hash_idx = (ctx->bank_hash_idx+1UL)%(sizeof(ctx->bank_hashes)/sizeof(ctx->bank_hashes[0]));
      ctx->bank_hash_cnt--;
      ctx->slot_cnt++;

      if( FD_UNLIKELY( msg->slot>=ctx->end_slot ) ) {
        ctx->replay_time    += fd_log_wallclock();
        double replay_time_s = (double)ctx->replay_time * 1e-9;
        double sec_per_slot  = replay_time_s / (double)ctx->slot_cnt;
        FD_LOG_NOTICE(( "Eqvoctest playback done. replay completed - slots: %lu, elapsed: %6.6f s, sec/slot: %6.6f", ctx->slot_cnt, replay_time_s, sec_per_slot ));
        exit(0);
      }
      break;
    }
    default: FD_LOG_ERR(( "unhandled in_kind: %d in_idx: %lu", ctx->in_kind[ in_idx ], in_idx ));
  }

  return 0;
}

static inline fd_eqvoct_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_eqvoct_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_eqvoct_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoct_tile_t),    sizeof(fd_eqvoct_tile_t) );
  void * _backtest_rocksdb = FD_SCRATCH_ALLOC_APPEND( l, fd_backtest_rocksdb_align(), fd_backtest_rocksdb_footprint() );

  ctx->initialized = 0;
  ctx->idle_cnt = 0UL;

  ctx->end_slot = tile->archiver.end_slot;
  ctx->slot_cnt = 0UL;

  ctx->shreds_idx = 0UL;
  ctx->shreds_cnt = 0UL;

  ctx->bank_hash_cnt = 0UL;
  ctx->bank_hash_idx = 0UL;

  ctx->reading_slot_cnt = 0UL;
  ctx->reading_shred_cnt = 0UL;
  ctx->reading_shred_idx = 0UL;

  ctx->chained_prev_slot = ULONG_MAX;
  ctx->prev_slot = ULONG_MAX;
  ctx->rocksdb = fd_backtest_rocksdb_join( fd_backtest_rocksdb_new( _backtest_rocksdb, tile->archiver.rocksdb_path /* TODO: Not arhiver */ ) );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  for( uint i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if(      !strcmp( link->name, "replay_out" ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "genesi_out" ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else FD_LOG_ERR(( "backtest tile has unexpected input link %s", link->name ));
  }

  *ctx->shred_out = out1( topo, tile, "shred_out" );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST                  (3UL) /* 1 after_credit + 1 returnable_frag */
#define STEM_CALLBACK_CONTEXT_TYPE  fd_eqvoct_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_eqvoct_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_eqvoctest = {
  .name                     = "eqvoct",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
