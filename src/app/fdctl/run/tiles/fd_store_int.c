/* Store tile manages a blockstore and serves requests to repair and replay. */

#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "generated/store_int_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../choreo/fd_choreo.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/tvu/fd_store.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/metrics/generated/fd_metrics_replay.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define SHRED_IN_IDX    0
#define REPAIR_IN_IDX   1
#define STAKE_IN_IDX    2
#define REPLAY_IN_IDX   3

#define REPAIR_OUT_IDX  0
#define REPLAY_OUT_IDX  1

/* TODO: Determine/justify optimal number of repair requests */
#define MAX_REPAIR_REQS  (32768UL)

#define SCRATCH_SMAX     (256UL << 21UL)
#define SCRATCH_SDEPTH   (128UL)

struct fd_store_tile_ctx {
  fd_wksp_t * wksp;
  fd_wksp_t * blockstore_wksp;

  fd_pubkey_t          identity_key[1]; /* Just the public key */

  fd_store_t * store;
  fd_blockstore_t * blockstore;

  fd_wksp_t * shred_in_mem;
  ulong       shred_in_chunk0;
  ulong       shred_in_wmark;

  fd_wksp_t * repair_in_mem;
  ulong       repair_in_chunk0;
  ulong       repair_in_wmark;

  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  fd_frag_meta_t * repair_req_out_mcache;
  ulong *          repair_req_out_sync;
  ulong            repair_req_out_depth;
  ulong            repair_req_out_seq;

  fd_wksp_t * repair_req_out_mem;
  ulong       repair_req_out_chunk0;
  ulong       repair_req_out_wmark;
  ulong       repair_req_out_chunk;

  fd_frag_meta_t * replay_out_mcache;
  ulong *          replay_out_sync;
  ulong            replay_out_depth;
  ulong            replay_out_seq;

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  fd_shred34_t s34_buffer[1];
  uchar shred_buffer[FD_SHRED_MAX_SZ];
  fd_txn_p_t pack_buffer[MAX_TXN_PER_MICROBLOCK];

  fd_repair_request_t * repair_req_buffer;

  fd_stake_ci_t * stake_ci;

  ulong blockstore_seed;

  ulong * root_slot_fseq;

  int sim;
};
typedef struct fd_store_tile_ctx fd_store_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 4UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_store_align(), fd_store_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_request_t), MAX_REPAIR_REQS * sizeof(fd_repair_request_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_SMAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_SDEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_store_tile_ctx_t) );
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq        FD_PARAM_UNUSED,
             ulong  sig        FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter FD_PARAM_UNUSED ) {
  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in_chunk0, ctx->stake_in_wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
  }

  if( FD_UNLIKELY( in_idx==SHRED_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->shred_in_chunk0 || chunk>ctx->shred_in_wmark || sz > sizeof(fd_shred34_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->shred_in_chunk0, ctx->shred_in_wmark ));
    }

    fd_shred34_t const * s34 = fd_chunk_to_laddr_const( ctx->shred_in_mem, chunk );

    memcpy( ctx->s34_buffer, s34, sz );
  }

  if( FD_UNLIKELY( in_idx==REPAIR_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->repair_in_chunk0 || chunk>ctx->repair_in_wmark || sz > FD_SHRED_MAX_SZ ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->repair_in_chunk0, ctx->repair_in_wmark ));
    }

    uchar const * shred = fd_chunk_to_laddr_const( ctx->repair_in_mem, chunk );

    memcpy( ctx->shred_buffer, shred, sz );
  }
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq          FD_PARAM_UNUSED,
            ulong *            opt_sig      FD_PARAM_UNUSED,
            ulong *            opt_chunk    FD_PARAM_UNUSED,
            ulong *            opt_sz       FD_PARAM_UNUSED,
            ulong *            opt_tsorig   FD_PARAM_UNUSED,
            int *              opt_filter   FD_PARAM_UNUSED,
            fd_mux_context_t * mux          FD_PARAM_UNUSED ) {

  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;

  ctx->store->now = fd_log_wallclock();

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( in_idx==SHRED_IN_IDX ) ) {
    for( ulong i = 0; i < ctx->s34_buffer->shred_cnt; i++ ) {
      // TODO: improve return value of api to not use < OK
      if( fd_store_shred_insert( ctx->store, &ctx->s34_buffer->pkts[i].shred ) < FD_BLOCKSTORE_OK ) {
        FD_LOG_ERR(( "failed inserting to blockstore" ));
      }

      fd_store_shred_update_with_shred_from_turbine( ctx->store, &ctx->s34_buffer->pkts[i].shred );
    }
  }

  if( FD_UNLIKELY( in_idx==REPAIR_IN_IDX ) ) {
    if( fd_store_shred_insert( ctx->store, fd_type_pun_const( ctx->shred_buffer ) ) < FD_BLOCKSTORE_OK ) {
      FD_LOG_ERR(( "failed inserting to blockstore" ));
    }
  }
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->store_int.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t *)fd_keyload_load( tile->store_int.identity_key_path, /* pubkey only: */ 1 );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->blockstore_seed, sizeof(ulong), 0 ) );
}

static void
fd_store_tile_slot_prepare( fd_store_tile_ctx_t * ctx,
                            int store_slot_prepare_mode,
                            ulong slot ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_repair_request_t * repair_reqs = fd_chunk_to_laddr( ctx->repair_req_out_mem, ctx->repair_req_out_chunk );
  fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, slot );

  fd_pubkey_t const * slot_leader = NULL;
  if( FD_LIKELY( !ctx->sim ) ) {
    if( FD_UNLIKELY( !lsched ) ) {
    // FD_LOG_WARNING(("Get leader schedule for slot %lu failed", slot));
      return;
    }

    slot_leader = fd_epoch_leaders_get( lsched, slot );
    if( FD_UNLIKELY( !slot_leader ) ) {
      FD_LOG_WARNING(( "Epoch leaders get fails" ));
      return;
    }
  }
  /* We are leader at this slot and the slot is newer than turbine! */
  // FIXME: I dont think that this `ctx->store->curr_turbine_slot >= slot`
  // check works on fork switches to lower slot numbers. Use a given fork height
  // instead
  // if( ctx->store->curr_turbine_slot >= slot
  //     && memcmp( ctx->identity_key, slot_leader, sizeof(fd_pubkey_t) ) == 0 ) {
  //   if( store_slot_prepare_mode == FD_STORE_SLOT_PREPARE_CONTINUE ) {
  //     fd_block_t * block = fd_blockstore_block_query( ctx->blockstore, slot );
  //     if( FD_LIKELY( block ) ) {
  //       block->flags = fd_uchar_set_bit( block->flags, FD_BLOCK_FLAG_PROCESSED );
  //     }
  //   } else {
  //     return;
  //   }
  // }

  ulong repair_req_cnt = 0;
  switch( store_slot_prepare_mode ) {
    case FD_STORE_SLOT_PREPARE_CONTINUE: {
      if( slot > 64UL ) {
        ctx->blockstore->smr = fd_ulong_max( ctx->blockstore->smr, slot - 64UL );
        fd_pending_slots_set_lo_wmark( ctx->store->pending_slots, ctx->blockstore->smr );
      }
      ctx->store->now = fd_log_wallclock();
      break;
    }
    case FD_STORE_SLOT_PREPARE_NEED_PARENT_EXEC: {
      break;
    }
    case FD_STORE_SLOT_PREPARE_NEED_REPAIR: {
      repair_req_cnt = fd_store_slot_repair( ctx->store, slot, repair_reqs, MAX_REPAIR_REQS );
      break;
    }
    case FD_STORE_SLOT_PREPARE_NEED_ORPHAN: {
      fd_repair_request_t * repair_req = &repair_reqs[0];
      repair_req->slot = slot;
      repair_req->shred_index = UINT_MAX;
      repair_req->type = FD_REPAIR_REQ_TYPE_NEED_ORPHAN;
      repair_req_cnt = 1;
      break;
    }
    case FD_STORE_SLOT_PREPARE_ALREADY_EXECUTED: {
      return;
    }
    default: {
      FD_LOG_ERR(( "unrecognized store slot prepare mode" ));
      return;
    }
  }

  if( store_slot_prepare_mode == FD_STORE_SLOT_PREPARE_CONTINUE ) {

    FD_LOG_NOTICE( ( "\n\n[Store]\n"
                     "slot:            %lu\n"
                     "current turbine: %lu\n"
                     "first turbine:   %lu\n"
                     "slots behind:    %lu\n"
                     "live:            %d\n",
                     slot,
                     ctx->store->curr_turbine_slot,
                     ctx->store->first_turbine_slot,
                     ctx->store->curr_turbine_slot - slot,
                     ( ctx->store->curr_turbine_slot - slot ) < 5 ) );

    uchar * out_buf = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );

    fd_block_t * block = fd_blockstore_block_query( ctx->blockstore, slot );
    if( block == NULL ) {
      FD_LOG_ERR(( "could not find block" ));
    }

    fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, slot );
    if( block_map_entry == NULL ) {
      FD_LOG_ERR(( "could not find slot meta" ));
    }

    fd_hash_t const * block_hash = fd_blockstore_block_hash_query( ctx->blockstore, slot );
    if( block_hash == NULL ) {
      FD_LOG_ERR(( "could not find slot meta" ));
    }

    FD_STORE( ulong, out_buf, block_map_entry->parent_slot );
    out_buf += sizeof(ulong);

    memcpy( out_buf, block_hash->uc, sizeof(fd_hash_t) );
    out_buf += sizeof(fd_hash_t);

    uchar * block_data = fd_blockstore_block_data_laddr( ctx->blockstore, block );

    FD_SCRATCH_SCOPE_BEGIN {
      fd_block_info_t block_info;
      fd_runtime_block_prepare( block_data, block->data_sz, fd_scratch_virtual(), &block_info );

      ulong caught_up = slot > ctx->store->first_turbine_slot;
      ulong behind = ctx->store->curr_turbine_slot - slot;

      FD_LOG_INFO(( "block prepared - slot: %lu, mblks: %lu, blockhash: %32J", slot, block_info.microblock_cnt, block_hash->uc ));
      FD_LOG_DEBUG(( "first turbine: %lu, current received turbine: %lu, behind: %lu current "
                      "executed: %lu, caught up: %d",
                      ctx->store->first_turbine_slot,
                      ctx->store->curr_turbine_slot,
                      behind,
                      slot,
                      caught_up ));

      FD_MGAUGE_SET( REPLAY, SLOT, ctx->store->curr_turbine_slot );
      FD_MGAUGE_SET( REPLAY, CAUGHT_UP, caught_up );
      FD_MGAUGE_SET( REPLAY, BEHIND, behind );

      fd_txn_p_t * txns = fd_type_pun( out_buf );
      ulong txn_cnt = fd_runtime_block_collect_txns( &block_info, txns );
 
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong caught_up_flag = (ctx->store->curr_turbine_slot - slot)==0 ? 0UL : REPLAY_FLAG_CATCHING_UP;
      ulong replay_sig = fd_disco_replay_sig( slot, REPLAY_FLAG_FINISHED_BLOCK | REPLAY_FLAG_MICROBLOCK | caught_up_flag );

      if( ( ctx->store->curr_turbine_slot - slot )==0 
          && slot_leader && memcmp( ctx->identity_key, slot_leader, sizeof(fd_pubkey_t) ) == 0 ) {
        /* if is caught up and is leader */
        txn_cnt = 0;
        replay_sig = fd_disco_replay_sig( slot, REPLAY_FLAG_FINISHED_BLOCK );
      }

      ulong out_sz = sizeof(ulong) + sizeof(fd_hash_t) + ( txn_cnt * sizeof(fd_txn_p_t) );
      fd_mcache_publish( ctx->replay_out_mcache, ctx->replay_out_depth, ctx->replay_out_seq, replay_sig, ctx->replay_out_chunk, txn_cnt, 0UL, tsorig, tspub );
      ctx->replay_out_seq   = fd_seq_inc( ctx->replay_out_seq, 1UL );
      ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, out_sz, ctx->replay_out_chunk0, ctx->replay_out_wmark );
    } FD_SCRATCH_SCOPE_END;
  }

  if( repair_req_cnt != 0 ) {
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    ulong repair_req_sig = 50UL;
    ulong repair_req_sz = repair_req_cnt * sizeof(fd_repair_request_t);
    fd_mcache_publish( ctx->repair_req_out_mcache, ctx->repair_req_out_depth, ctx->repair_req_out_seq, repair_req_sig, ctx->repair_req_out_chunk,
      repair_req_cnt, 0UL, tsorig, tspub );
    ctx->repair_req_out_seq   = fd_seq_inc( ctx->repair_req_out_seq, 1UL );
    ctx->repair_req_out_chunk = fd_dcache_compact_next( ctx->repair_req_out_chunk, repair_req_sz, ctx->repair_req_out_chunk0, ctx->repair_req_out_wmark );
  }

  return;
}

static void
after_credit( void *             _ctx,
	            fd_mux_context_t * mux_ctx FD_PARAM_UNUSED,
              int *              opt_poll_in FD_PARAM_UNUSED ) {
  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;

  fd_mcache_seq_update( ctx->replay_out_sync, ctx->replay_out_seq );
  fd_mcache_seq_update( ctx->repair_req_out_sync, ctx->repair_req_out_seq );

  ctx->store->now = fd_log_wallclock();

  if( FD_UNLIKELY( ctx->sim &&
                   ctx->store->pending_slots->start == ctx->store->pending_slots->end ) ) {
    FD_LOG_ERR( ( "Sim is complete." ) );
  }

  for( ulong i = fd_pending_slots_iter_init( ctx->store->pending_slots );
         (i = fd_pending_slots_iter_next( ctx->store->pending_slots, ctx->store->now, i )) != ULONG_MAX; ) {
    uchar const * block = NULL;
    ulong         block_sz = 0;
    ulong repair_slot = FD_SLOT_NULL;
    int store_slot_prepare_mode = fd_store_slot_prepare( ctx->store, i, &repair_slot, &block, &block_sz );

    ulong slot = repair_slot == 0 ? i : repair_slot;
    FD_LOG_DEBUG(( "store slot - mode: %d, slot: %lu, repair_slot: %lu", store_slot_prepare_mode, i, repair_slot ));
    fd_store_tile_slot_prepare( ctx, store_slot_prepare_mode, slot );
  }
}

void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  fd_flamenco_boot( NULL, NULL );

  if( FD_UNLIKELY( tile->in_cnt != 3 ||
                   strcmp( topo->links[ tile->in_link_id[ SHRED_IN_IDX     ] ].name, "shred_storei" )    ||
                   strcmp( topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ].name, "repair_store" ) ) )
    FD_LOG_ERR(( "store tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( tile->out_cnt != 2 ||
                   strcmp( topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ].name, "store_repair" ) ||
                   strcmp( topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ].name, "store_replay" ) ) )
    FD_LOG_ERR(( "store tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( tile->out_link_id_primary != ULONG_MAX ) )
    FD_LOG_ERR(( "store tile has a primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  // TODO: set the lo_mark_slot to the actual snapshot slot!
  ctx->store = fd_store_join( fd_store_new( FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(), fd_store_footprint() ), 1 ) );
  ctx->repair_req_buffer = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_request_t), MAX_REPAIR_REQS * sizeof(fd_repair_request_t) );
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );
  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_SMAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_SDEPTH ) );

  /* Create scratch region */
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, SCRATCH_SMAX, SCRATCH_SDEPTH );


  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;

  if( ctx->blockstore_wksp == NULL ) {
    FD_LOG_ERR(( "blockstore_wksp must be defined in topo." ));
  }

  /**********************************************************************/
  /* root_slot fseq                                                     */
  /**********************************************************************/
  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->root_slot_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->root_slot_fseq ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->root_slot_fseq ) );

  /* Prevent blockstore from being created until we know the shred version */
  ulong expected_shred_version = tile->shred.expected_shred_version;
  if( FD_LIKELY( !expected_shred_version ) ) {
    ulong busy_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    FD_LOG_INFO(( "waiting for shred version to be determined via gossip." ));
    do {
      expected_shred_version = FD_VOLATILE_CONST( *gossip_shred_version );
    } while( expected_shred_version==ULONG_MAX );
  }

  if( FD_UNLIKELY( strlen( tile->store_int.blockstore_restore ) > 0 ) ) {
    FD_LOG_NOTICE(( "starting blockstore_wksp restore %s", tile->store_int.blockstore_restore ));
    int rc = fd_wksp_restore( ctx->blockstore_wksp, tile->store_int.blockstore_restore, (uint)FD_BLOCKSTORE_MAGIC );
    if( rc ) {
      FD_LOG_ERR(( "failed to restore %s: error %d.", tile->store_int.blockstore_restore, rc ));
    }
    FD_LOG_NOTICE(( "finished blockstore_wksp restore %s", tile->store_int.blockstore_restore ));
    fd_wksp_tag_query_info_t info;
    ulong tag = FD_BLOCKSTORE_MAGIC;
    if (fd_wksp_tag_query(ctx->blockstore_wksp, &tag, 1, &info, 1) > 0) {
      void * blockstore_mem = fd_wksp_laddr_fast( ctx->blockstore_wksp, info.gaddr_lo );
      ctx->blockstore       = fd_blockstore_join( blockstore_mem );
    } else {
      FD_LOG_WARNING(( "failed to find blockstore in workspace. making new blockstore." ));
    }
  } else {
    void * blockstore_shmem = fd_wksp_alloc_laddr( ctx->blockstore_wksp,
                                                 fd_blockstore_align(),
                                                 fd_blockstore_footprint(),
                                                 FD_BLOCKSTORE_MAGIC );
    if( blockstore_shmem == NULL ) {
      FD_LOG_ERR(( "failed to alloc blockstore" ));
    }

    ctx->blockstore = fd_blockstore_join( fd_blockstore_new( blockstore_shmem, 1, ctx->blockstore_seed, FD_BUF_SHRED_MAP_MAX, FD_BLOCK_MAX, FD_TXN_MAP_LG_MAX ) );
  }

  FD_TEST( ctx->blockstore );
  ctx->store->blockstore = ctx->blockstore;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) {
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) );
  }

  /* Set up shred tile input */
  fd_topo_link_t * shred_in_link = &topo->links[ tile->in_link_id[ SHRED_IN_IDX ] ];
  ctx->shred_in_mem    = topo->workspaces[ topo->objs[ shred_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_in_chunk0 = fd_dcache_compact_chunk0( ctx->shred_in_mem, shred_in_link->dcache );
  ctx->shred_in_wmark  = fd_dcache_compact_wmark( ctx->shred_in_mem, shred_in_link->dcache, shred_in_link->mtu );

  /* Set up repair tile input */
  fd_topo_link_t * repair_in_link = &topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ];
  ctx->repair_in_mem    = topo->workspaces[ topo->objs[ repair_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_in_chunk0 = fd_dcache_compact_chunk0( ctx->repair_in_mem, repair_in_link->dcache );
  ctx->repair_in_wmark  = fd_dcache_compact_wmark( ctx->repair_in_mem, repair_in_link->dcache, repair_in_link->mtu );

  /* Set up stake tile input */
  fd_topo_link_t * stake_in_link = &topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ];
  ctx->stake_in_mem    = topo->workspaces[ topo->objs[ stake_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  /* Set up replay tile input */
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ REPLAY_IN_IDX ] ];
  ctx->replay_in_mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  /* Set up repair request output */
  fd_topo_link_t * repair_req_out = &topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ];
  ctx->repair_req_out_mcache = repair_req_out->mcache;
  ctx->repair_req_out_sync   = fd_mcache_seq_laddr( ctx->repair_req_out_mcache );
  ctx->repair_req_out_depth  = fd_mcache_depth( ctx->repair_req_out_mcache );
  ctx->repair_req_out_seq    = fd_mcache_seq_query( ctx->repair_req_out_sync );
  ctx->repair_req_out_mem    = topo->workspaces[ topo->objs[ repair_req_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_req_out_chunk0 = fd_dcache_compact_chunk0( ctx->repair_req_out_mem, repair_req_out->dcache );
  ctx->repair_req_out_wmark  = fd_dcache_compact_wmark ( ctx->repair_req_out_mem, repair_req_out->dcache, repair_req_out->mtu );
  ctx->repair_req_out_chunk  = ctx->repair_req_out_chunk0;

  /* Set up replay output */
  fd_topo_link_t * replay_out = &topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ];
  ctx->replay_out_mcache = replay_out->mcache;
  ctx->replay_out_sync   = fd_mcache_seq_laddr( ctx->replay_out_mcache );
  ctx->replay_out_depth  = fd_mcache_depth( ctx->replay_out_mcache );
  ctx->replay_out_seq    = fd_mcache_seq_query( ctx->replay_out_sync );
  ctx->replay_out_mem    = topo->workspaces[ topo->objs[ replay_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, replay_out->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_out_mem, replay_out->dcache, replay_out->mtu );
  ctx->replay_out_chunk  = ctx->replay_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }

  if( FD_UNLIKELY( strlen( tile->store_int.slots_pending ) > 0 ) ) {
    ctx->sim = 1;

    const char * split = strchr( tile->store_int.slots_pending, '-' );
    FD_TEST( split != NULL && *( split + 1 ) != '\0' );
    const char * snapshot_slot_str = split + 1;
    char *       endptr;
    ulong        snapshot_slot = strtoul( snapshot_slot_str, &endptr, 10 );

    FILE * file = fopen( tile->store_int.slots_pending, "r" );
    char   buf[20]; /* max # of digits for a ulong */

    ulong cnt = 1;
    fd_blockstore_start_write( ctx->blockstore );
    FD_TEST( fd_block_map_remove( fd_blockstore_block_map (ctx->blockstore), &snapshot_slot ) );
    while( fgets( buf, sizeof( buf ), file ) ) {
      char *       endptr;
      ulong        slot  = strtoul( buf, &endptr, 10 );
      fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, slot );
      block_map_entry->flags       = 0;
      fd_store_add_pending( ctx->store, slot, cnt++ );
    }
    fd_blockstore_end_write( ctx->blockstore );
    fclose( file );
  }
}

static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_store_int( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_store_int_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch     FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_store_int = {
  .name                     = "storei",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
