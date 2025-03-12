/* Store tile manages a blockstore and serves requests to repair and replay. */
#include "fd_store.h"
#define _GNU_SOURCE

#include "generated/fd_storei_tile_seccomp.h"

#include "fd_trusted_slots.h"
#include "../shred/fd_shred_cap.h"

#include "../../disco/tiles.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../disco/metrics/fd_metrics.h"

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define STAKE_IN_IDX    0
#define REPAIR_IN_IDX   1
#define RESTART_IN_IDX  2
#define NON_SHRED_LINKS 3 /* stake, repair, and replay are the 3 links not from shred tile */

#define REPLAY_OUT_IDX  0
#define REPAIR_OUT_IDX  1
#define RESTART_OUT_IDX 2

/* TODO: Determine/justify optimal number of repair requests */
#define MAX_REPAIR_REQS  ( (ulong)USHORT_MAX / sizeof(fd_repair_request_t) )

#define SCRATCH_SMAX     (512UL << 21UL)
#define SCRATCH_SDEPTH   (128UL)

struct fd_txn_iter {
  ulong slot;
  fd_raw_block_txn_iter_t iter;
};

typedef struct fd_txn_iter fd_txn_iter_t;

#define MAP_NAME              fd_txn_iter_map
#define MAP_T                 fd_txn_iter_t
#define MAP_KEY_T             ulong
#define MAP_KEY               slot
#define MAP_KEY_NULL          FD_SLOT_NULL
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, FD_SLOT_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (k0==k1)
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( key ))
#define MAP_LG_SLOT_CNT       5
#include "../../util/tmpl/fd_map.c"

struct fd_store_in_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_store_in_ctx fd_store_in_ctx_t;

struct fd_store_tile_metrics {
  ulong first_turbine_slot;
  ulong current_turbine_slot;
};
typedef struct fd_store_tile_metrics fd_store_tile_metrics_t;
#define FD_STORE_TILE_METRICS_FOOTPRINT ( sizeof( fd_store_tile_metrics_t ) )

struct fd_store_tile_ctx {
  fd_wksp_t * wksp;
  fd_wksp_t * blockstore_wksp;

  fd_pubkey_t identity_key[1]; /* Just the public key */

  fd_store_t *      store;
  fd_blockstore_t   blockstore_ljoin;
  int               blockstore_fd; /* file descriptor for archival file */
  fd_blockstore_t * blockstore;

  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  fd_wksp_t * repair_in_mem;
  ulong       repair_in_chunk0;
  ulong       repair_in_wmark;

  fd_wksp_t * restart_in_mem;
  ulong       restart_in_chunk0;
  ulong       restart_in_wmark;

  ulong             shred_in_cnt;
  fd_store_in_ctx_t shred_in[ 32 ];

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

  fd_frag_meta_t * restart_out_mcache;
  ulong *          restart_out_sync;
  ulong            restart_out_depth;
  ulong            restart_out_seq;

  fd_wksp_t * restart_out_mem;
  ulong       restart_out_chunk0;
  ulong       restart_out_wmark;
  ulong       restart_out_chunk;

  fd_shred34_t s34_buffer[1];
  uchar shred_buffer[FD_SHRED_MAX_SZ];
  fd_txn_p_t pack_buffer[MAX_TXN_PER_MICROBLOCK];

  fd_repair_request_t * repair_req_buffer;

  fd_stake_ci_t * stake_ci;

  ulong * root_slot_fseq;

  int sim;
  ulong sim_end_slot;

  fd_shred_cap_ctx_t shred_cap_ctx;

  fd_trusted_slots_t * trusted_slots;
  int                  is_trusted;

  fd_txn_iter_t * txn_iter_map;

  ulong restart_funk_root;
  ulong restart_heaviest_fork_slot;

  /* Metrics */
  fd_store_tile_metrics_t metrics;

  ulong turbine_cnt;
  ulong repair_cnt;
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
  l = FD_LAYOUT_APPEND( l, fd_trusted_slots_align(), fd_trusted_slots_footprint( MAX_SLOTS_PER_EPOCH ) );
  l = FD_LAYOUT_APPEND( l, fd_txn_iter_map_align(), fd_txn_iter_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_SMAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_SDEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
during_frag( fd_store_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in_chunk0, ctx->stake_in_wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( in_idx==REPAIR_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->repair_in_chunk0 || chunk>ctx->repair_in_wmark || sz > FD_SHRED_MAX_SZ ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->repair_in_chunk0, ctx->repair_in_wmark ));
    }

    uchar const * shred = fd_chunk_to_laddr_const( ctx->repair_in_mem, chunk );

    memcpy( ctx->shred_buffer, shred, sz );
    return;
  }

  if( FD_UNLIKELY( in_idx==RESTART_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->restart_in_chunk0 || chunk>ctx->restart_in_wmark || sz>sizeof(ulong)*2 ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->restart_in_chunk0, ctx->restart_in_wmark ));
    }

    FD_TEST( sz==sizeof(ulong)*2 );
    if( FD_UNLIKELY( ctx->restart_heaviest_fork_slot!=0 ) ) {
      FD_LOG_ERR(( "Store tile should only receive heaviest_fork_slot once during wen-restart. Something may have corrupted." ));
    }
    const uchar * buf               = fd_chunk_to_laddr_const( ctx->restart_in_mem, chunk );
    ctx->restart_heaviest_fork_slot = FD_LOAD( ulong, buf );
    ctx->restart_funk_root          = FD_LOAD( ulong, buf+sizeof(ulong) );

    return;
  }

  /* everything else is shred tiles */
  fd_store_in_ctx_t * shred_in = &ctx->shred_in[ in_idx-NON_SHRED_LINKS ];
  if( FD_UNLIKELY( chunk<shred_in->chunk0 || chunk>shred_in->wmark || sz > sizeof(fd_shred34_t) ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, shred_in->chunk0 , shred_in->wmark ));
  }

  ctx->is_trusted = sig==1;
  fd_shred34_t const * s34 = fd_chunk_to_laddr_const( shred_in->mem, chunk );

  memcpy( ctx->s34_buffer, s34, sz );
}

static void
after_frag( fd_store_tile_ctx_t * ctx,
            ulong                 in_idx,
            ulong                 seq    FD_PARAM_UNUSED,
            ulong                 sig    FD_PARAM_UNUSED,
            ulong                 sz     FD_PARAM_UNUSED,
            ulong                 tsorig FD_PARAM_UNUSED,
            ulong                 tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *   stem   FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( in_idx==REPAIR_IN_IDX ) ) {
    fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( ctx->shred_buffer );
    if( !fd_pending_slots_check( ctx->store->pending_slots, shred->slot ) ) {
      FD_LOG_WARNING(("received repair shred %lu that would overrun pending queue. skipping.", shred->slot));
      return;
    }

    if( FD_UNLIKELY( (long)(ctx->store->curr_turbine_slot - shred->slot) > (long)8192 ) ) {
      FD_LOG_WARNING(("received repair shred with slot %lu that would overrun pending queue. skipping.", shred->slot));
      return;
    }

    if( fd_store_shred_insert( ctx->store, shred ) < FD_BLOCKSTORE_SUCCESS ) {
      FD_LOG_ERR(( "failed inserting to blockstore" ));
    } else if ( ctx->shred_cap_ctx.is_archive ) {
      uchar shred_cap_flag = FD_SHRED_CAP_FLAG_MARK_REPAIR( 0 );
      if( fd_shred_cap_archive( &ctx->shred_cap_ctx, shred, shred_cap_flag ) < FD_SHRED_CAP_OK ) {
        FD_LOG_ERR( ( "failed at archiving repair shred to file" ) );
      }
    }
    ctx->repair_cnt++;
    return;
  }

  if( FD_UNLIKELY( in_idx==RESTART_IN_IDX ) ) {
    FD_LOG_NOTICE(( "Store tile starts to repair backwards from slot%lu, which should be on the same fork as slot%lu",
                    ctx->restart_heaviest_fork_slot, ctx->restart_funk_root ));
    fd_store_add_pending( ctx->store, ctx->restart_heaviest_fork_slot, (long)5e6, 0, 0 );
    return;
  }

  /* everything else is shred */
  FD_TEST( ctx->s34_buffer->shred_cnt>0UL );

  if( FD_UNLIKELY( ctx->is_trusted ) ) {
    /* this slot is coming from our leader pipeline */
    fd_trusted_slots_add( ctx->trusted_slots, ctx->s34_buffer->pkts[ 0 ].shred.slot );
  }
  for( ulong i = 0; i < ctx->s34_buffer->shred_cnt; i++ ) {
    fd_shred_t * shred = &ctx->s34_buffer->pkts[i].shred;
    // TODO: these checks are not great as they assume a lot about the distance of shreds.
    if( !fd_pending_slots_check( ctx->store->pending_slots, shred->slot ) ) {
      FD_LOG_WARNING(("received shred %lu that would overrun pending queue. skipping.", shred->slot));
      continue;
    }

    if( FD_UNLIKELY( (long)(ctx->store->curr_turbine_slot - shred->slot) > (long)8192 ) ) {
      FD_LOG_WARNING(("received shred with slot %lu that would overrun pending queue. skipping.", shred->slot));
      continue;
    }
    // TODO: improve return value of api to not use < OK

    if( fd_store_shred_insert( ctx->store, shred ) < FD_BLOCKSTORE_SUCCESS ) {
      FD_LOG_ERR(( "failed inserting to blockstore" ));
    } else if ( ctx->shred_cap_ctx.is_archive ) {
      uchar shred_cap_flag = FD_SHRED_CAP_FLAG_MARK_TURBINE(0);
      if ( fd_shred_cap_archive(&ctx->shred_cap_ctx, shred, shred_cap_flag) < FD_SHRED_CAP_OK ) {
        FD_LOG_ERR(( "failed at archiving turbine shred to file" ));
      }
    }
    ctx->turbine_cnt++;

    fd_store_shred_update_with_shred_from_turbine( ctx->store, shred );
  }
}

static void
fd_store_tile_slot_prepare( fd_store_tile_ctx_t * ctx,
                            fd_stem_context_t *  stem,
                            int                  store_slot_prepare_mode,
                            ulong                slot ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_repair_request_t * repair_reqs = fd_chunk_to_laddr( ctx->repair_req_out_mem, ctx->repair_req_out_chunk );
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
      ulong root = fd_fseq_query( ctx->root_slot_fseq );
      if( root!=ULONG_MAX ) {
        // FD_LOG_WARNING(("CONTINUE: %lu", root));
        fd_store_set_root( ctx->store, root );
      }
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

    if ( FD_UNLIKELY( ctx->sim && slot>=ctx->sim_end_slot ) ) {
      FD_LOG_ERR(( "Finished simulation to slot %lu", ctx->sim_end_slot ));
    }

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

    if( !fd_blockstore_shreds_complete( ctx->blockstore, slot ) ) {
      FD_LOG_ERR(( "could not find block - slot: %lu", slot ));
    }

    ulong parent_slot = fd_blockstore_parent_slot_query( ctx->blockstore, slot );
    if ( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) FD_LOG_ERR(( "could not find slot %lu meta", slot ));

    FD_STORE( ulong, out_buf, parent_slot );
    out_buf += sizeof(ulong);
    int err = fd_blockstore_block_hash_query( ctx->blockstore, slot, (fd_hash_t *)fd_type_pun( out_buf ) );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "could not find slot meta" ));
    out_buf += sizeof(fd_hash_t);

    FD_SCRATCH_SCOPE_BEGIN {
      ctx->metrics.first_turbine_slot = ctx->store->first_turbine_slot;
      ctx->metrics.current_turbine_slot = ctx->store->curr_turbine_slot;

      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong caught_up_flag = (ctx->store->curr_turbine_slot - slot)<4 ? 0UL : REPLAY_FLAG_CATCHING_UP;
      ulong replay_sig = fd_disco_replay_old_sig( slot, REPLAY_FLAG_MICROBLOCK | caught_up_flag );

      ulong txn_cnt = 0;
      if( FD_UNLIKELY( fd_trusted_slots_find( ctx->trusted_slots, slot ) ) ) {
        /* if is caught up and is leader */
        replay_sig = fd_disco_replay_old_sig( slot, REPLAY_FLAG_FINISHED_BLOCK );
        FD_LOG_INFO(( "packed block prepared - slot: %lu", slot ));
      } else {
        replay_sig = fd_disco_replay_old_sig( slot, REPLAY_FLAG_FINISHED_BLOCK | REPLAY_FLAG_MICROBLOCK | caught_up_flag );
      }

      out_buf += sizeof(ulong);

      ulong out_sz = sizeof(ulong) + sizeof(fd_hash_t) + ( txn_cnt * sizeof(fd_txn_p_t) );
      fd_stem_publish( stem, 0UL, replay_sig, ctx->replay_out_chunk, txn_cnt, 0UL, tsorig, tspub );
      ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, out_sz, ctx->replay_out_chunk0, ctx->replay_out_wmark );
    } FD_SCRATCH_SCOPE_END;
  }

  if( repair_req_cnt != 0 ) {
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    ulong repair_req_sig = 50UL;
    ulong repair_req_sz = repair_req_cnt * sizeof(fd_repair_request_t);
    FD_TEST( repair_req_sz<=USHORT_MAX );
    fd_mcache_publish( ctx->repair_req_out_mcache, ctx->repair_req_out_depth, ctx->repair_req_out_seq, repair_req_sig, ctx->repair_req_out_chunk,
      repair_req_sz, 0UL, tsorig, tspub );
    ctx->repair_req_out_seq   = fd_seq_inc( ctx->repair_req_out_seq, 1UL );
    ctx->repair_req_out_chunk = fd_dcache_compact_next( ctx->repair_req_out_chunk, repair_req_sz, ctx->repair_req_out_chunk0, ctx->repair_req_out_wmark );
  }

  return;
}

static void
after_credit( fd_store_tile_ctx_t * ctx,
              fd_stem_context_t *   stem,
              int *                 opt_poll_in FD_PARAM_UNUSED,
              int *                 charge_busy ) {
  /* TODO: Don't charge the tile as busy if after_credit isn't actually
     doing any work. */
  *charge_busy = 1;

  fd_mcache_seq_update( ctx->replay_out_sync, ctx->replay_out_seq );
  fd_mcache_seq_update( ctx->repair_req_out_sync, ctx->repair_req_out_seq );

  if( FD_UNLIKELY( ctx->sim &&
                   ctx->store->pending_slots->start == ctx->store->pending_slots->end ) ) {
    // FD_LOG_WARNING(( "Sim is complete." ));
  }

  for( ulong i = 0; i<fd_txn_iter_map_slot_cnt(); i++ ) {
    if( ctx->txn_iter_map[i].slot != FD_SLOT_NULL ) {
      fd_store_tile_slot_prepare( ctx, stem, FD_STORE_SLOT_PREPARE_CONTINUE, ctx->txn_iter_map[i].slot );
    }
  }

  for( ulong i = fd_pending_slots_iter_init( ctx->store->pending_slots );
         (i = fd_pending_slots_iter_next( ctx->store->pending_slots, ctx->store->now, i )) != ULONG_MAX; ) {
    ulong repair_slot = FD_SLOT_NULL;
    int store_slot_prepare_mode = fd_store_slot_prepare( ctx->store, i, &repair_slot );

    ulong slot = repair_slot == 0 ? i : repair_slot;
    FD_LOG_DEBUG(( "store slot - mode: %d, slot: %lu, repair_slot: %lu", store_slot_prepare_mode, i, repair_slot ));
    fd_store_tile_slot_prepare( ctx, stem, store_slot_prepare_mode, slot );

    if( FD_UNLIKELY( ctx->restart_heaviest_fork_slot &&
                     i==ctx->restart_heaviest_fork_slot ) ) {
      if( FD_LIKELY( store_slot_prepare_mode!=FD_STORE_SLOT_PREPARE_ALREADY_EXECUTED ) ) {
        fd_store_add_pending( ctx->store, ctx->restart_heaviest_fork_slot, (long)5e6, 0, 0 );
      } else {
        fd_hash_t blk_hash;
        int err = fd_blockstore_block_hash_query( ctx->blockstore,
                                                  ctx->restart_heaviest_fork_slot,
                                                  &blk_hash );
        if( FD_UNLIKELY( err ) ){
          FD_LOG_ERR(( "Wen-restart cannot get the block hash of HeaviestForkSlot %lu", ctx->restart_heaviest_fork_slot ));
        }
        fd_funk_txn_xid_t xid;
        fd_memcpy( &xid, &blk_hash, sizeof(fd_funk_txn_xid_t) );
        xid.ul[0] = ctx->restart_heaviest_fork_slot;

        /* Send xid to restart tile */
        uchar * buf   = fd_chunk_to_laddr( ctx->restart_out_mem, ctx->restart_out_chunk );
        ulong buf_len = sizeof(fd_funk_txn_xid_t);
        fd_memcpy( buf, &xid, sizeof(fd_funk_txn_xid_t) );
        fd_mcache_publish( ctx->restart_out_mcache, ctx->restart_out_depth, ctx->restart_out_seq, 1UL, ctx->restart_out_chunk,
                           buf_len, 0UL, 0, 0 );
        ctx->restart_out_seq   = fd_seq_inc( ctx->restart_out_seq, 1UL );
        ctx->restart_out_chunk = fd_dcache_compact_next( ctx->restart_out_chunk, buf_len, ctx->restart_out_chunk0, ctx->restart_out_wmark );
      }
    }
  }
}

static inline void
during_housekeeping( fd_store_tile_ctx_t * ctx ) {
  ctx->store->now = fd_log_wallclock();
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( !strcmp( tile->store_int.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->store_int.identity_key_path, /* pubkey only: */ 1 ) );
  ctx->blockstore_fd = open( tile->store_int.blockstore_file, O_RDONLY );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt < 3 ||
                   strcmp( topo->links[ tile->in_link_id[ STAKE_IN_IDX  ] ].name, "stake_out" )   ||
                   strcmp( topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ].name, "repair_store") ||
                   strcmp( topo->links[ tile->in_link_id[ RESTART_IN_IDX ] ].name,"rstart_store") ) )
    FD_LOG_ERR(( "store tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( tile->out_cnt != 3 ||
                   strcmp( topo->links[ tile->out_link_id[ REPLAY_OUT_IDX ] ].name, "store_replay" ) ||
                   strcmp( topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ].name, "store_repair" ) ||
                   strcmp( topo->links[ tile->out_link_id[ RESTART_OUT_IDX ] ].name, "store_rstart" )) )
    FD_LOG_ERR(( "store tile has none or unexpected output links %lu %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  ctx->blockstore = &ctx->blockstore_ljoin;
  // TODO: set the lo_mark_slot to the actual snapshot slot!
  ctx->store = fd_store_join( fd_store_new( FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(), fd_store_footprint() ), 1 ) );
  ctx->repair_req_buffer = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_request_t), MAX_REPAIR_REQS * sizeof(fd_repair_request_t) );
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );

  void * trusted_slots_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_trusted_slots_align(), fd_trusted_slots_footprint( MAX_SLOTS_PER_EPOCH ) );
  ctx->trusted_slots = fd_trusted_slots_join( fd_trusted_slots_new( trusted_slots_mem, MAX_SLOTS_PER_EPOCH ) );
  FD_TEST( ctx->trusted_slots!=NULL );

  void * iter_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_txn_iter_map_align(), fd_txn_iter_map_footprint() );
  ctx->txn_iter_map = fd_txn_iter_map_join( fd_txn_iter_map_new( iter_map_mem ) );

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
  ulong expected_shred_version = tile->store_int.expected_shred_version;
  if( FD_LIKELY( !expected_shred_version ) ) {
    ulong busy_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    FD_LOG_INFO(( "waiting for shred version to be determined via gossip." ));
    do {
      expected_shred_version = fd_fseq_query( gossip_shred_version );
    } while( expected_shred_version==ULONG_MAX );
    FD_LOG_NOTICE(( "using shred version %lu", expected_shred_version ));
  }
  if( FD_UNLIKELY( expected_shred_version>USHORT_MAX ) ) FD_LOG_ERR(( "invalid shred version %lu", expected_shred_version ));
  FD_TEST( expected_shred_version );
  fd_store_expected_shred_version( ctx->store, expected_shred_version );

  if( FD_UNLIKELY( strlen( tile->store_int.blockstore_restore ) > 0 ) ) {
    FD_LOG_NOTICE(( "starting blockstore_wksp restore %s", tile->store_int.blockstore_restore ));
    int rc = fd_wksp_restore( ctx->blockstore_wksp, tile->store_int.blockstore_restore, (uint)FD_BLOCKSTORE_MAGIC );
    if( rc ) {
      FD_LOG_ERR(( "failed to restore %s: error %d.", tile->store_int.blockstore_restore, rc ));
    }
    FD_LOG_NOTICE(( "finished blockstore_wksp restore %s", tile->store_int.blockstore_restore ));
    fd_wksp_tag_query_info_t info;
    ulong tag = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.wksp_tag", blockstore_obj_id );
    if( FD_LIKELY( fd_wksp_tag_query( ctx->blockstore_wksp, &tag, 1, &info, 1 ) > 0 ) ) {
      void * blockstore_mem = fd_wksp_laddr_fast( ctx->blockstore_wksp, info.gaddr_lo );
      ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, blockstore_mem );
    } else {
      FD_LOG_WARNING(( "failed to find blockstore in workspace. making new blockstore." ));
    }
  } else {
    void * blockstore_shmem = fd_topo_obj_laddr( topo, blockstore_obj_id );
    if( blockstore_shmem == NULL ) {
      FD_LOG_ERR(( "failed to find blockstore" ));
    }

    ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, blockstore_shmem );
  }

  FD_LOG_NOTICE(( "blockstore: %s", tile->store_int.blockstore_file ));

  FD_TEST( ctx->blockstore );
  ctx->store->blockstore = ctx->blockstore;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) {
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) );
  }

  /* Set up stake tile input */
  fd_topo_link_t * stake_in_link = &topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ];
  ctx->stake_in_mem    = topo->workspaces[ topo->objs[ stake_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  /* Set up repair tile input */
  fd_topo_link_t * repair_in_link = &topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ];
  ctx->repair_in_mem    = topo->workspaces[ topo->objs[ repair_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_in_chunk0 = fd_dcache_compact_chunk0( ctx->repair_in_mem, repair_in_link->dcache );
  ctx->repair_in_wmark  = fd_dcache_compact_wmark( ctx->repair_in_mem, repair_in_link->dcache, repair_in_link->mtu );

  /* Set up replay tile input (for wen-restart) */
  fd_topo_link_t * restart_in_link = &topo->links[ tile->in_link_id[ RESTART_IN_IDX ] ];
  ctx->restart_in_mem    = topo->workspaces[ topo->objs[ restart_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->restart_in_chunk0 = fd_dcache_compact_chunk0( ctx->restart_in_mem, restart_in_link->dcache );
  ctx->restart_in_wmark  = fd_dcache_compact_wmark( ctx->restart_in_mem, restart_in_link->dcache, restart_in_link->mtu );

  /* Set up ctx states for wen-restart */
  ctx->restart_funk_root          = 0;
  ctx->restart_heaviest_fork_slot = 0;

  /* Set up shred tile inputs */
  ctx->shred_in_cnt = tile->in_cnt-NON_SHRED_LINKS;
  for( ulong i = 0; i<ctx->shred_in_cnt; i++ ) {
    fd_topo_link_t * shred_in_link = &topo->links[ tile->in_link_id[ i+NON_SHRED_LINKS ] ];
    ctx->shred_in[ i ].mem    = topo->workspaces[ topo->objs[ shred_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->shred_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->shred_in[ i ].mem, shred_in_link->dcache );
    ctx->shred_in[ i ].wmark  = fd_dcache_compact_wmark( ctx->shred_in[ i ].mem, shred_in_link->dcache, shred_in_link->mtu );
  }

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

  /* Set up replay output */
  fd_topo_link_t * restart_out = &topo->links[ tile->out_link_id[ RESTART_OUT_IDX ] ];
  ctx->restart_out_mcache = restart_out->mcache;
  ctx->restart_out_sync   = fd_mcache_seq_laddr( ctx->restart_out_mcache );
  ctx->restart_out_depth  = fd_mcache_depth( ctx->restart_out_mcache );
  ctx->restart_out_seq    = fd_mcache_seq_query( ctx->restart_out_sync );
  ctx->restart_out_mem    = topo->workspaces[ topo->objs[ restart_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->restart_out_chunk0 = fd_dcache_compact_chunk0( ctx->restart_out_mem, restart_out->dcache );
  ctx->restart_out_wmark  = fd_dcache_compact_wmark ( ctx->restart_out_mem, restart_out->dcache, restart_out->mtu );
  ctx->restart_out_chunk  = ctx->restart_out_chunk0;

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_SMAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_SDEPTH ) );

  /* Create scratch region */
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, SCRATCH_SMAX, SCRATCH_SDEPTH );

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
    FD_TEST( fd_blockstore_block_info_remove( ctx->blockstore, snapshot_slot ) );

    while( fgets( buf, sizeof( buf ), file ) ) {
      char *       endptr;
      ulong        slot  = strtoul( buf, &endptr, 10 );
      fd_block_map_query_t query[1] = { 0 };
      int err = fd_block_map_prepare( ctx->blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
      fd_block_info_t * block_map_entry = fd_block_map_query_ele( query );
      if( err || block_map_entry->slot != slot ) {
        FD_LOG_ERR(( "init: slot %lu does not match block_map_entry->slot %lu", slot, block_map_entry->slot ));
      }
      block_map_entry->flags = 0;
      fd_block_map_publish( query );
      fd_store_add_pending( ctx->store, slot, (long)cnt++, 0, 0 );
    }
    fclose( file );
  }

  ctx->shred_cap_ctx.is_archive        = 0;
  ctx->shred_cap_ctx.stable_slot_end   = 0;
  ctx->shred_cap_ctx.stable_slot_start = 0;
  if( strlen( tile->store_int.shred_cap_archive ) > 0 ) {
    ctx->shred_cap_ctx.is_archive      = 1;
    ctx->shred_cap_ctx.shred_cap_fileno = open( tile->store_int.shred_cap_archive,
                                                O_WRONLY | O_CREAT,
                                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( ctx->shred_cap_ctx.shred_cap_fileno==-1 ) FD_LOG_ERR(( "failed at opening the shredcap file" ));
  } else if( strlen( tile->store_int.shred_cap_replay )>0 ) {
    ctx->sim                           = 1;
    ctx->sim_end_slot                  = tile->store_int.shred_cap_end_slot;
    FD_LOG_WARNING(( "simulating to slot %lu", ctx->sim_end_slot ));
    ctx->store->blockstore->shmem->wmk = 0UL;
    while( ctx->store->blockstore->shmem->wmk==0UL ) {
      FD_LOG_DEBUG(( "Waiting for blockstore to be initialized" ));
    }
    FD_TEST( fd_shred_cap_replay( tile->store_int.shred_cap_replay, ctx->store ) == FD_SHRED_CAP_OK );
  }

}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  populate_sock_filter_policy_fd_storei_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->blockstore_fd );
  return sock_filter_policy_fd_storei_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_store_tile_ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = STDERR_FILENO;
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->blockstore_fd;
  return out_cnt;
}

static inline void
metrics_write( fd_store_tile_ctx_t * ctx ) {
  FD_MGAUGE_SET( STOREI, CURRENT_TURBINE_SLOT, ctx->metrics.current_turbine_slot );
  FD_MGAUGE_SET( STOREI, FIRST_TURBINE_SLOT, ctx->metrics.first_turbine_slot );
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_store_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_store_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_store_int = {
  .name                     = "storei",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
