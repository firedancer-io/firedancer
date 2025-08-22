#include "../../disco/stem/fd_stem.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../util/pod/fd_pod_format.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_SNAP   (1)
#define MAX_IN_LINKS   (16)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {

  /* Flag for whether after_credit can publish another FEC set to
     progress replay */

  int credit;

  /* Metadata */

  ulong root;
  ulong staged_root;
  ulong start_slot;
  ulong end_slot;
  long  replay_time;
  ulong slot_cnt;

  ulong start_from_genesis;

  /* Used by RocksDB and bank hash check. TODO refactor those APIs to
     not alloc. */

  fd_valloc_t valloc;

  /* Manifest is received from the snap_out link to discover the
     snapshot slot (TODO block id) */

  fd_snapshot_manifest_t snapshot_manifest;

  /* RocksDB-related ctx for iterating shreds in RocksDB and checking
     bank hash */

  fd_rocksdb_t           rocksdb;
  rocksdb_iterator_t *   rocksdb_iter;
  fd_rocksdb_root_iter_t rocksdb_root_iter;
  fd_slot_meta_t         rocksdb_slot_meta;
  ulong                  rocksdb_curr_idx;
  ulong                  rocksdb_end_idx;
  ulong                  rocksdb_end_slot;
  uchar *                rocksdb_bank_hash;

  /* Store-related ctx for reconstructing shreds from RocksDB into FEC
     sets */

  fd_store_t *           store;
  fd_shred_t const *     curr;
  fd_hash_t              prev_mr;

  /* Links */

  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  fd_wksp_t *           replay_out_mem;
  ulong                 replay_out_chunk0;
  ulong                 replay_out_wmark;
  ulong                 replay_out_chunk;
  ulong                 replay_out_idx;
  fd_replay_slot_info_t replay_slot_info;

  ulong root_out_idx;

} ctx_t;

/* shred_merkle_root returns a copy of shred's merkle root. */

fd_hash_t
shred_merkle_root( fd_shred_t const * shred ) {
  fd_bmtree_node_t bmtree_root;
  uchar bmtree_mem[fd_bmtree_commit_footprint( 10UL )]__attribute__( ( aligned( FD_BMTREE_COMMIT_ALIGN ) ) );
  fd_shred_merkle_root( shred, bmtree_mem, &bmtree_root );
  fd_hash_t mr;
  memcpy( &mr, &bmtree_root, sizeof(fd_bmtree_node_t) );
  return mr;
}

/* rocksdb_next_shred returns the next shred from the RocksDB iterator's
   current position. */

static fd_shred_t const *
rocksdb_next_shred( ctx_t * ctx,
                   ulong * out_sz ) {
  if( ctx->rocksdb_curr_idx==ctx->rocksdb_end_idx ) {
    if( FD_UNLIKELY( fd_rocksdb_root_iter_next( &ctx->rocksdb_root_iter, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
    if( FD_UNLIKELY( fd_rocksdb_get_meta( &ctx->rocksdb, ctx->rocksdb_slot_meta.slot, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
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

/* rocksdb_check_bank_hash checks the bank hash for slot against what is
   recorded in RocksDB. */

static void
rocksdb_check_bank_hash( ctx_t * ctx, ulong slot, fd_hash_t * bank_hash ) {
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

  if( ( slot!=ctx->start_slot && ctx->start_slot!=ULONG_MAX ) || ( ctx->start_from_genesis ) ) {
    ctx->slot_cnt++;
    if( FD_LIKELY( !memcmp( bank_hash, &versioned->inner.current.frozen_hash, sizeof(fd_hash_t) ) ) ) {
      FD_LOG_NOTICE(( "Bank hash matches! slot=%lu, hash=%s", slot, FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
    } else {
      /* Do not change this log as it is used in offline replay */
      FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s", slot, FD_BASE58_ENC_32_ALLOCA( versioned->inner.current.frozen_hash.hash ), FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
    }
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
      alignof(ctx_t),   sizeof(ctx_t)        ),
      fd_alloc_align(), fd_alloc_footprint() ),
    scratch_align()
  );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) { /* needed for fd_alloc */
  return 2UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->credit ) )                 return;
  if( FD_UNLIKELY( !fd_store_root( ctx->store ) ) ) return; /* replay initializes this */
  FD_TEST( ctx->root!=ULONG_MAX ); /* corruption */

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  /* Collect shreds from RocksDB using the iterator until we can recons
     a FEC set. */

  ulong sz;
  fd_shred_t const * prev = NULL;
  fd_shred_t const * curr = ctx->curr ? ctx->curr : rocksdb_next_shred( ctx, &sz );
  if( FD_UNLIKELY ( !curr ) ) return; /* finished replay */

  fd_hash_t mr = shred_merkle_root( curr );
  fd_store_shacq ( ctx->store );
  fd_store_insert( ctx->store, 0, &mr );
  fd_store_shrel ( ctx->store );
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
    curr = rocksdb_next_shred( ctx, &sz );
    if( FD_UNLIKELY( !curr || curr->fec_set_idx != prev->fec_set_idx || curr->slot != prev->slot ) ) break;
  }
  FD_TEST( prev );

  /* We're guaranteed to iterate slots in order from RocksDB (linear
     chain) so link the merkle roots to the previous one. */

  fd_store_exacq ( ctx->store );
  fd_store_link( ctx->store, &mr, &ctx->prev_mr );
  fd_store_exrel( ctx->store );

  /* Instead of using the shred->chained_mr, there's a known issue where
  the cluster can converge on bad chained merkle roots across slots.  So
  we just track the previous mr ourselves vs. relying on chained mr. */

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

  ulong sig = out.slot << 32 | out.fec_set_idx;
  memcpy( fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk ), &out, sizeof(fd_reasm_fec_t) );
  fd_stem_publish( stem, ctx->replay_out_idx, sig, ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), 0, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );

  ctx->curr = curr;
  if( out.slot_complete ) ctx->credit = 0;

  *charge_busy = 1;
  return; /* yield after publish one FEC set */
}

static inline int
before_frag( ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  switch( in_kind ) {
  case IN_KIND_REPLAY: /* no op */                                                 return 0;
  case IN_KIND_SNAP:   ctx->credit = fd_ssmsg_sig_message( sig ) == FD_SSMSG_DONE; return ctx->credit;
  default:             FD_LOG_ERR(( "unhandled in_kind: %u in_idx: %lu", in_kind, in_idx ));
  }
}

static void
during_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig FD_PARAM_UNUSED,
             ulong   chunk,
             ulong   sz FD_PARAM_UNUSED,
             ulong   ctl FD_PARAM_UNUSED ) {
  uint          in_kind     = ctx->in_kind[in_idx];
  uchar const * chunk_laddr = fd_chunk_to_laddr( ctx->in_links[in_idx].mem, chunk );
  switch( in_kind ) {
  case IN_KIND_REPLAY: memcpy( &ctx->replay_slot_info,  chunk_laddr, sizeof(fd_replay_slot_info_t ) ); break;
  case IN_KIND_SNAP:   memcpy( &ctx->snapshot_manifest, chunk_laddr, sizeof(fd_snapshot_manifest_t) ); break;
  default:             FD_LOG_ERR(( "unhandled in_kind: %u in_idx: %lu", in_kind, in_idx ));
  }
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq FD_PARAM_UNUSED,
            ulong               sig FD_PARAM_UNUSED,
            ulong               sz FD_PARAM_UNUSED,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  switch( in_kind ) {
  case IN_KIND_REPLAY: {
    ulong slot = ctx->replay_slot_info.slot;
    if ( slot==0 ) {
      ctx->start_from_genesis = 1;
      ctx->root = 0UL; /* Set root for genesis case */
      ctx->start_slot = 0UL; /* Set start_slot for genesis case */
      ctx->replay_time = -fd_log_wallclock(); /* Start timing for genesis case */

      /* Initialize RocksDB iterator for genesis case, similar to snapshot case */
      fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
      if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, ctx->root, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) {
        FD_LOG_CRIT(( "Failed at seeking rocksdb root iter for slot=%lu", ctx->root ));
      }
      ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);
    }
    rocksdb_check_bank_hash( ctx, slot, &ctx->replay_out.bank_hash );
    if( FD_UNLIKELY( slot>=ctx->end_slot ) ) {
      ctx->replay_time    += fd_log_wallclock();
      double replay_time_s = (double)ctx->replay_time * 1e-9;
      double sec_per_slot  = replay_time_s / (double)ctx->slot_cnt;
      FD_LOG_NOTICE(( "replay completed - slots: %lu, elapsed: %6.6f s, sec/slot: %6.6f", ctx->slot_cnt, replay_time_s, sec_per_slot ));
      FD_LOG_ERR(( "Backtest playback done." ));
    } else {

      /* Delay publishing by 1 slot otherwise there is a replay tile race when it tries to query the parent. */

      if( FD_UNLIKELY( ctx->staged_root!=ULONG_MAX || ctx->start_from_genesis ) ) fd_stem_publish( stem, ctx->root_out_idx, ctx->staged_root, 0, sizeof(fd_hash_t), 0UL, tspub, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->staged_root = slot;
      ctx->credit = 1;
    }
    break;
  }
  case IN_KIND_SNAP: {
    if( FD_UNLIKELY( ctx->root != ULONG_MAX ) ) FD_LOG_CRIT(( "backtest got multiple manifests" ));
    ctx->root        = ctx->snapshot_manifest.slot;
    ctx->start_slot  = ctx->snapshot_manifest.slot;
    ctx->replay_time = -fd_log_wallclock();

    fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
    if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, ctx->root, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) {
      FD_LOG_CRIT(( "Failed at seeking rocksdb root iter for slot=%lu", ctx->root ));
    }
    ctx->rocksdb_iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);
    break;
  }
  default: FD_LOG_ERR(( "unhandled in_kind: %u in_idx: %lu", in_kind, in_idx ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx               = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),   sizeof(ctx_t)        );
  void  * alloc_shmem       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  ulong   scratch_top       = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align()                        );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );

  ctx->credit = 0;

  ctx->root        = ULONG_MAX;
  ctx->staged_root = ULONG_MAX;
  ctx->start_slot  = ULONG_MAX;
  ctx->end_slot    = tile->archiver.end_slot;
  ctx->replay_time = LONG_MAX;
  ctx->slot_cnt    = 0UL;

  ctx->start_from_genesis = 0;

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, 1 ), 1 );
  FD_TEST( alloc );
  ctx->valloc = fd_alloc_virtual( alloc );

  ctx->rocksdb_curr_idx = 0;
  ctx->rocksdb_end_idx  = 0;
  fd_memset( &ctx->rocksdb, 0, sizeof(fd_rocksdb_t) );
  fd_memset( &ctx->rocksdb_slot_meta, 0, sizeof(fd_slot_meta_t) );
  fd_memset( &ctx->rocksdb_root_iter, 0, sizeof(fd_rocksdb_root_iter_t) );
  fd_rocksdb_init( &ctx->rocksdb, tile->archiver.rocksdb_path );
  char * err = NULL;
  ulong rocksdb_end_slot = fd_rocksdb_last_slot( &ctx->rocksdb, &err );
  if( FD_UNLIKELY( err!=NULL ) ) FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", err ));
  if( FD_UNLIKELY( rocksdb_end_slot<ctx->end_slot ) ) FD_LOG_ERR(( "RocksDB only has shreds up to slot=%lu, so it cannot playback to end_slot=%lu", rocksdb_end_slot, ctx->end_slot ));
  ctx->rocksdb_end_slot=rocksdb_end_slot;
  ctx->rocksdb_bank_hash = fd_valloc_malloc( ctx->valloc, fd_frozen_hash_versioned_align(), sizeof(fd_frozen_hash_versioned_t) );
  FD_TEST( ctx->rocksdb_bank_hash );

  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );
  ctx->curr = NULL;
  ctx->prev_mr = (fd_hash_t){0};

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if(        0==strcmp( link->name, "replay_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
    } else if( 0==strcmp( link->name, "snap_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    } else {
      FD_LOG_ERR(( "backtest tile has unexpected input link %s", link->name ));
    }
    in_ctx_t * in = &ctx->in_links[in_idx];
    in->mem       = topo->workspaces[topo->objs[link->dcache_obj_id].wksp_id].wksp;
    in->chunk0    = fd_dcache_compact_chunk0( in->mem, link->dcache );
    in->wmark     = fd_dcache_compact_wmark( in->mem, link->dcache, link->mtu );
    in->mtu       = link->mtu;
  }

  ctx->replay_out_idx    = fd_topo_find_tile_out_link( topo, tile, "repair_repla", 0 );
  FD_TEST( ctx->replay_out_idx!=ULONG_MAX );
  fd_topo_link_t * link  = &topo->links[ tile->out_link_id[ ctx->replay_out_idx ] ];
  ctx->replay_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, link->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark( ctx->replay_out_mem, link->dcache, link->mtu );
  ctx->replay_out_chunk  = ctx->replay_out_chunk0;

  ctx->root_out_idx = fd_topo_find_tile_out_link( topo, tile, "root_out", 0 );
  FD_TEST( ctx->root_out_idx!=ULONG_MAX );
  /* no root_out dcache */
}

#define STEM_BURST                  (2UL) /* 1 after_credit + 1 after_frag*/
#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
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
