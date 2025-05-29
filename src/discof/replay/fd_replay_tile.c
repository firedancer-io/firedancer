#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "fd_replay_notif.h"
#include "../restart/fd_restart.h"
#include "fd_epoch_forks.h"

#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_runtime_init.h"
#include "../../flamenco/snapshot/fd_snapshot.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../choreo/fd_choreo.h"
#include "../../funk/fd_funk_filemap.h"
#include "../../flamenco/snapshot/fd_snapshot_create.h"
#include "../../disco/plugin/fd_plugin.h"
#include "fd_exec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEQUE_NAME fd_exec_slice
#define DEQUE_T    ulong
#define DEQUE_MAX  USHORT_MAX + 1
#include "../../util/tmpl/fd_deque.c"

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_BLK_MAX * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )

#define PLUGIN_PUBLISH_TIME_NS ((long)60e9)

#define REPAIR_IN_IDX  (0UL)
#define PACK_IN_IDX    (1UL)
#define BATCH_IN_IDX   (2UL)
#define SHRED_IN_IDX   (3UL)

#define STAKE_OUT_IDX  (0UL)
#define SENDER_OUT_IDX (1UL)
#define POH_OUT_IDX    (2UL)

#define EXEC_BOOT_WAIT  (0UL)
#define EXEC_BOOT_DONE  (1UL)
#define EXEC_EPOCH_WAIT (2UL)
#define EXEC_EPOCH_DONE (3UL)
#define EXEC_SLOT_WAIT  (4UL)
#define EXEC_TXN_BUSY   (5UL)
#define EXEC_TXN_READY  (6UL)

#define BANK_HASH_CMP_LG_MAX (16UL)

struct fd_replay_out_link {
  ulong            idx;

  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;

};
typedef struct fd_replay_out_link fd_replay_out_link_t;

struct fd_replay_tile_metrics {
  ulong slot;
  ulong last_voted_slot;
};
typedef struct fd_replay_tile_metrics fd_replay_tile_metrics_t;
#define FD_REPLAY_TILE_METRICS_FOOTPRINT ( sizeof( fd_replay_tile_metrics_t ) )

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;
  fd_wksp_t * blockstore_wksp;
  fd_wksp_t * funk_wksp;
  fd_wksp_t * status_cache_wksp;

  fd_wksp_t  * runtime_public_wksp;
  fd_runtime_public_t * runtime_public;

  // Store tile input
  fd_wksp_t * repair_in_mem;
  ulong       repair_in_chunk0;
  ulong       repair_in_wmark;

  // Pack tile input
  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  // Batch tile input for epoch account hash
  fd_wksp_t * batch_in_mem;
  ulong       batch_in_chunk0;
  ulong       batch_in_wmark;

  // Notification output defs
  fd_replay_out_link_t notif_out[1];

  // Sender output defs
  fd_replay_out_link_t sender_out[1];

  // Stake weights output link defs
  fd_replay_out_link_t stake_weights_out[1];

  // Inputs to plugin/gui
  fd_replay_out_link_t plugin_out[1];
  fd_replay_out_link_t votes_plugin_out[1];
  long                 last_plugin_push_time;

  char const * blockstore_checkpt;
  int          tx_metadata_storage;
  char const * funk_checkpt;
  char const * genesis;
  char const * incremental;
  char const * snapshot;
  char const * snapshot_dir;
  int          incremental_src_type;
  int          snapshot_src_type;

  /* Do not modify order! This is join-order in unprivileged_init. */

  fd_funk_t             funk[1];
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_epoch_t          * epoch;
  fd_forks_t          * forks;
  fd_ghost_t          * ghost;
  fd_tower_t          * tower;

  fd_pubkey_t validator_identity[1];
  fd_pubkey_t vote_authority[1];
  fd_pubkey_t vote_acc[1];

  /* Vote accounts in the current epoch. Lifetimes of the vote account
     addresses (pubkeys) are valid for the epoch (the pubkey memory is
     owned by the epoch bank). */

  fd_voter_t         * epoch_voters;  /* Map chain of slot->voter */
  fd_bank_hash_cmp_t * bank_hash_cmp; /* Maintains bank hashes seen from votes */

  /* Blockstore local join */

  fd_blockstore_t   blockstore_ljoin;
  int               blockstore_fd; /* file descriptor for archival file */
  fd_blockstore_t * blockstore;

  /* Updated during execution */

  fd_exec_slot_ctx_t  * slot_ctx;
  fd_slice_exec_t       slice_exec_ctx;

  /* TODO: Some of these arrays should be bitvecs that get masked into. */
  ulong                exec_cnt;
  fd_replay_out_link_t exec_out  [ FD_PACK_MAX_BANK_TILES ]; /* Sending to exec unexecuted txns */
  uchar                exec_ready[ FD_PACK_MAX_BANK_TILES ]; /* Is tile ready */
  uint                 prev_ids  [ FD_PACK_MAX_BANK_TILES ]; /* Previous txn id if any */
  ulong *              exec_fseq [ FD_PACK_MAX_BANK_TILES ]; /* fseq of the last executed txn */
  int                  block_finalizing;

  ulong                writer_cnt;
  ulong *              writer_fseq[ FD_PACK_MAX_BANK_TILES ];
  fd_replay_out_link_t writer_out [ FD_PACK_MAX_BANK_TILES ];

  /* Metadata updated during execution */

  ulong   curr_slot;
  ulong   parent_slot;
  ulong   snapshot_slot;
  ulong * curr_turbine_slot;
  ulong   root; /* the root slot is the most recent slot to have reached
                   max lockout in the tower  */
  ulong   flags;
  ulong   bank_idx;

  /* Other metadata */

  ulong funk_seed;
  ulong status_cache_seed;
  fd_capture_ctx_t * capture_ctx;
  FILE *             capture_file;
  FILE *             slots_replayed_file;

  ulong * bank_busy[ FD_PACK_MAX_BANK_TILES ];
  ulong   bank_cnt;
  fd_replay_out_link_t bank_out[ FD_PACK_MAX_BANK_TILES ]; /* Sending to PoH finished txns + a couple more tasks ??? */


  ulong * published_wmark; /* publish watermark. The watermark is defined as the
                  minimum of the tower root (root above) and blockstore
                  smr (blockstore->smr). The watermark is used to
                  publish our fork-aware structures eg. blockstore,
                  forks, ghost. In general, publishing has the effect of
                  pruning minority forks in those structures,
                  indicating that is ok to release the memory being
                  occupied by said forks.

                  The reason it has to be the minimum of the two, is the
                  tower root can lag the SMR and vice versa, but both
                  the fork-aware structures need to maintain information
                  through both of those slots. */

  ulong * poh;  /* proof-of-history slot */
  uint poh_init_done;
  int  snapshot_init_done;

  int         tower_checkpt_fileno;

  int         vote;
  fd_pubkey_t validator_identity_pubkey[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_txncache_t * status_cache;
  void * bmtree[ FD_PACK_MAX_BANK_TILES ];

  fd_epoch_forks_t epoch_forks[1];

  /* The spad allocators used by the executor tiles are NOT the same as the
     spad used for general, longer-lasting spad allocations. The lifetime of
     the exec spad is just through an execution. The runtime spad is scoped
     to the runtime. The top-most frame will persist for the entire duration
     of the process. There will also be a potential second frame that persists
     across multiple slots that is created for rewards distrobution. Every other
     spad frame should NOT exist beyond the scope of a block. */

  fd_spad_t *         exec_spads[ FD_PACK_MAX_BANK_TILES ];
  fd_wksp_t *         exec_spads_wksp[ FD_PACK_MAX_BANK_TILES ];
  fd_exec_txn_ctx_t * exec_txn_ctxs[ FD_PACK_MAX_BANK_TILES ];
  ulong               exec_spad_cnt;

  fd_spad_t *         runtime_spad;

  /* TODO: refactor this all into fd_replay_tile_snapshot_ctx_t. */
  ulong   snapshot_interval;        /* User defined parameter */
  ulong   incremental_interval;     /* User defined parameter */
  ulong   last_full_snap;           /* If a full snapshot has been produced */
  ulong * is_constipated;           /* Shared fseq to determine if funk should be constipated */
  ulong   prev_full_snapshot_dist;  /* Tracking for snapshot creation */
  ulong   prev_incr_snapshot_dist;  /* Tracking for incremental snapshot creation */

  fd_funk_txn_t * false_root;

  int is_caught_up;

  int blocked_on_mblock; /* Flag used for synchronizing on mblock boundaries. */

  /* Metrics */
  fd_replay_tile_metrics_t metrics;

  ulong * exec_slice_deque; /* Deque to buffer exec slices - lives in spad */
};
typedef struct fd_replay_tile_ctx fd_replay_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 24UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {

  /* Do not modify order! This is join-order in unprivileged_init. */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  l = FD_LAYOUT_APPEND( l, 128UL, FD_SLICE_MAX );
  l = FD_LAYOUT_FINI  ( l, scratch_align() );
  return l;
}

/* Receives from repair newly completed slices of executable slots on
   the frontier. Guaranteed good properties, like happiness, in order,
   executable immediately as long as the mcache wasn't overrun. */
static int
before_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig ) {
  (void)seq;

  if( in_idx==REPAIR_IN_IDX ) {
    FD_LOG_DEBUG(( "rx slice from repair tile %lu %u", fd_disco_repair_replay_sig_slot( sig ), fd_disco_repair_replay_sig_data_cnt( sig ) ));
    fd_exec_slice_push_tail( ctx->exec_slice_deque, sig );
    return 1;
  } else if( in_idx==SHRED_IN_IDX ) {
    return 1;
  }
  return 0;
}

static void
during_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz  FD_PARAM_UNUSED,
             ulong                  ctl FD_PARAM_UNUSED ) {

  if( in_idx==BATCH_IN_IDX ) {
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->batch_in_mem, chunk );
    fd_memcpy( ctx->slot_ctx->slot_bank.epoch_account_hash.uc, src, sizeof(fd_hash_t) );
    FD_LOG_NOTICE(( "Epoch account hash calculated to be %s", FD_BASE58_ENC_32_ALLOCA( ctx->slot_ctx->slot_bank.epoch_account_hash.uc ) ));
  }
}

/* Large number of helpers for after_credit begin here  */

static void
publish_stake_weights( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t *    stem,
                       fd_exec_slot_ctx_t *   slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if( slot_ctx->slot_bank.epoch_stakes.vote_accounts_root!=NULL ) {
    ulong *             stake_weights_msg = fd_chunk_to_laddr( ctx->stake_weights_out->mem,
                                                               ctx->stake_weights_out->chunk );
    ulong epoch = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot );
    ulong stake_weights_sz = generate_stake_weight_msg( slot_ctx, ctx->runtime_spad, epoch - 1, stake_weights_msg );
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_weights_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->stake_weights_out->chunk = fd_dcache_compact_next( ctx->stake_weights_out->chunk, stake_weights_sz, ctx->stake_weights_out->chunk0, ctx->stake_weights_out->wmark );
    FD_LOG_NOTICE(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
  }

  if( epoch_bank->next_epoch_stakes.vote_accounts_root!=NULL ) {
    ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_weights_out->mem, ctx->stake_weights_out->chunk );
    ulong   epoch             = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule,
                                                                  slot_ctx->slot_bank.slot ); /* epoch */
    ulong stake_weights_sz = generate_stake_weight_msg( slot_ctx, ctx->runtime_spad, epoch, stake_weights_msg );
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_weights_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->stake_weights_out->chunk = fd_dcache_compact_next( ctx->stake_weights_out->chunk, stake_weights_sz, ctx->stake_weights_out->chunk0, ctx->stake_weights_out->wmark );
    FD_LOG_NOTICE(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
  }
}

static void
snapshot_hash_tiles_cb( void * para_arg_1,
                        void * para_arg_2,
                        void * fn_arg_1,
                        void * fn_arg_2 FD_PARAM_UNUSED,
                        void * fn_arg_3 FD_PARAM_UNUSED,
                        void * fn_arg_4 FD_PARAM_UNUSED ) {

  fd_replay_tile_ctx_t    * ctx       = (fd_replay_tile_ctx_t *)para_arg_1;
  fd_stem_context_t       * stem      = (fd_stem_context_t    *)para_arg_2;
  fd_subrange_task_info_t * task_info = (fd_subrange_task_info_t *)fn_arg_1;

  ulong num_lists = ctx->exec_cnt;
  FD_LOG_NOTICE(( "launching %lu hash tasks", num_lists ));
  fd_pubkey_hash_pair_list_t * lists         = fd_spad_alloc( ctx->runtime_spad, alignof(fd_pubkey_hash_pair_list_t), num_lists * sizeof(fd_pubkey_hash_pair_list_t) );
  fd_lthash_value_t *          lthash_values = fd_spad_alloc( ctx->runtime_spad, FD_LTHASH_VALUE_ALIGN, num_lists * FD_LTHASH_VALUE_FOOTPRINT );
  for( ulong i = 0; i < num_lists; i++ ) {
    fd_lthash_zero( &lthash_values[i] );
  }

  task_info->num_lists     = num_lists;
  task_info->lists         = lists;
  task_info->lthash_values = lthash_values;

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    fd_stem_publish( stem, ctx->exec_out[i].idx, EXEC_SNAP_HASH_ACCS_CNT_SIG, ctx->exec_out[i].chunk, 0UL, 0UL, 0UL, 0UL );
    ctx->exec_out[i].chunk = fd_dcache_compact_next( ctx->exec_out[i].chunk, 0UL, ctx->exec_out[i].chunk0, ctx->exec_out[i].wmark );
  }

  uchar cnt_done[ FD_PACK_MAX_BANK_TILES ] = {0};
  for( ;; ) {
    uchar wait_cnt = 0;
    for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
      if( !cnt_done[ i ] ) {
        ulong res   = fd_fseq_query( ctx->exec_fseq[ i ] );
        uint  state = fd_exec_fseq_get_state( res );
        if( state==FD_EXEC_STATE_SNAP_CNT_DONE ) {
          FD_LOG_DEBUG(( "Acked hash cnt msg" ));
          cnt_done[ i ] = 1;
          task_info->lists[ i ].pairs = fd_spad_alloc( ctx->runtime_spad,
                                                       FD_PUBKEY_HASH_PAIR_ALIGN,
                                                       fd_exec_fseq_get_pairs_len( res ) * sizeof(fd_pubkey_hash_pair_t) );
        } else {
          wait_cnt++;
        }
      }
    }
    if( !wait_cnt ) {
      break;
    }
  }

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {

    fd_replay_out_link_t * exec_out = &ctx->exec_out[ i ];

    fd_runtime_public_snap_hash_msg_t * gather_msg = (fd_runtime_public_snap_hash_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );

    gather_msg->lt_hash_value_out_gaddr = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, &lthash_values[i] );
    gather_msg->num_pairs_out_gaddr     = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, &task_info->lists[i].pairs_len );
    gather_msg->pairs_gaddr             = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, task_info->lists[i].pairs );

    fd_stem_publish( stem, ctx->exec_out[i].idx, EXEC_SNAP_HASH_ACCS_GATHER_SIG, ctx->exec_out[i].chunk, sizeof(fd_runtime_public_snap_hash_msg_t), 0UL, 0UL, 0UL );
    ctx->exec_out[i].chunk = fd_dcache_compact_next( ctx->exec_out[i].chunk, sizeof(fd_runtime_public_snap_hash_msg_t), ctx->exec_out[i].chunk0, ctx->exec_out[i].wmark );
  }


  memset( cnt_done, 0, sizeof(cnt_done) );
  for( ;; ) {
    uchar wait_cnt = 0;
    for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
      if( !cnt_done[ i ] ) {
        ulong res   = fd_fseq_query( ctx->exec_fseq[ i ] );
        uint  state = fd_exec_fseq_get_state( res );
        if( state==FD_EXEC_STATE_SNAP_GATHER_DONE ) {
          FD_LOG_DEBUG(( "Acked hash gather msg" ));
          cnt_done[ i ] = 1;
        } else {
          wait_cnt++;
        }
      }
    }
    if( !wait_cnt ) {
      break;
    }
  }
}


static void
bpf_tiles_cb( void * para_arg_1,
              void * para_arg_2,
              void * fn_arg_1,
              void * fn_arg_2,
              void * fn_arg_3,
              void * fn_arg_4 FD_PARAM_UNUSED ) {
  fd_replay_tile_ctx_t  * ctx            = (fd_replay_tile_ctx_t *)para_arg_1;
  fd_stem_context_t     * stem           = (fd_stem_context_t *)para_arg_2;
  fd_funk_rec_t const * * recs           = (fd_funk_rec_t const **)fn_arg_1;
  uchar *                 is_bpf_program = (uchar *)fn_arg_2;
  ulong                   rec_cnt        = (ulong)fn_arg_3;

  ulong cnt_per_worker = rec_cnt / ctx->exec_cnt;

  ulong recs_gaddr   = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, recs );
  if( FD_UNLIKELY( !recs_gaddr ) ) {
    FD_LOG_ERR(( "Unable to calculate gaddr for recs arary" ));
  }

  ulong is_bpf_gaddr = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, is_bpf_program );
  if( FD_UNLIKELY( !is_bpf_gaddr ) ) {
    FD_LOG_ERR(( "Unable to calculate gaddr for is bpf array" ));
  }

  /* We need to keep track of the previous state because we don't want
     to duplicate write cache entries back into funk. If we are in an
     uninitialized state, we set our previous id to UINT_MAX */
  uint prev_ids[ FD_PACK_MAX_BANK_TILES ];
  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ulong res   = fd_fseq_query( ctx->exec_fseq[ i ] );
    uint  state = fd_exec_fseq_get_state( res );
    if( state==FD_EXEC_STATE_BPF_SCAN_DONE ) {
      prev_ids[ i ] = fd_exec_fseq_get_bpf_id( res );
    } else {
      prev_ids[ i ] = FD_EXEC_ID_SENTINEL;
    }
  }

  for( ulong worker_idx=0UL; worker_idx<ctx->exec_cnt; worker_idx++ ) {

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong start_idx = worker_idx * cnt_per_worker;
    ulong end_idx   = worker_idx!=ctx->exec_cnt-1UL ? fd_ulong_sat_sub( start_idx + cnt_per_worker, 1UL ) :
                                                      fd_ulong_sat_sub( rec_cnt, 1UL );
    fd_replay_out_link_t * exec_out = &ctx->exec_out[ worker_idx ];

    fd_runtime_public_bpf_scan_msg_t * scan_msg = (fd_runtime_public_bpf_scan_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
    generate_bpf_scan_msg( start_idx, end_idx, recs_gaddr, is_bpf_gaddr, scan_msg );
    fd_stem_publish( stem,
                     exec_out->idx,
                     EXEC_BPF_SCAN_SIG,
                     exec_out->chunk,
                     sizeof(fd_runtime_public_bpf_scan_msg_t),
                     0UL,
                     tsorig,
                     fd_frag_meta_ts_comp( fd_tickcount() ) );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk,
                                              sizeof(fd_runtime_public_bpf_scan_msg_t),
                                              exec_out->chunk0,
                                              exec_out->wmark );

  }

  /* Spins and blocks until all exec tiles are done scanning. */
  uchar scan_done[ FD_PACK_MAX_BANK_TILES ] = {0};
  for( ;; ) {
    uchar wait_cnt = 0;
    for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
      if( !scan_done[ i ] ) {
        ulong res   = fd_fseq_query( ctx->exec_fseq[ i ] );
        uint  state = fd_exec_fseq_get_state( res );
        uint  id    = fd_exec_fseq_get_bpf_id( res );
        if( state==FD_EXEC_STATE_BPF_SCAN_DONE && id!=prev_ids[ i ] ) {
          scan_done[ i ] = 1;
          prev_ids[ i ]  = id;
        } else {
          wait_cnt++;
        }
      }
    }
    if( !wait_cnt ) {
      break;
    }
  }

}

static void
block_finalize_tiles_cb( void * para_arg_1,
                         void * para_arg_2,
                         void * fn_arg_1,
                         void * fn_arg_2 FD_PARAM_UNUSED,
                         void * fn_arg_3 FD_PARAM_UNUSED,
                         void * fn_arg_4 FD_PARAM_UNUSED ) {

  fd_replay_tile_ctx_t *         ctx        = (fd_replay_tile_ctx_t *)para_arg_1;
  fd_stem_context_t *            stem       = (fd_stem_context_t *)para_arg_2;
  fd_accounts_hash_task_data_t * task_data  = (fd_accounts_hash_task_data_t *)fn_arg_1;

  ulong cnt_per_worker;
  if( ctx->exec_cnt>1 ) cnt_per_worker = (task_data->info_sz / (ctx->exec_cnt-1UL)) + 1UL; /* ??? */
  else                  cnt_per_worker = task_data->info_sz;
  ulong task_infos_gaddr = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, task_data->info );

  uchar hash_done[ FD_PACK_MAX_BANK_TILES ] = {0};
  for( ulong worker_idx=0UL; worker_idx<ctx->exec_cnt; worker_idx++ ) {

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong lt_hash_gaddr = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, &task_data->lthash_values[ worker_idx ] );
    if( FD_UNLIKELY( !lt_hash_gaddr ) ) {
      FD_LOG_ERR(( "lt_hash_gaddr is NULL" ));
      return;
    }

    ulong start_idx = worker_idx * cnt_per_worker;
    if( start_idx >= task_data->info_sz ) {
      /* If we do not any work for this worker to do, skip it. */
      hash_done[ worker_idx ] = 1;
      continue;
    }
    ulong end_idx = fd_ulong_sat_sub( start_idx + cnt_per_worker, 1UL );
    if( end_idx >= task_data->info_sz ) {
      end_idx = fd_ulong_sat_sub( task_data->info_sz, 1UL );
    }

    fd_replay_out_link_t * exec_out = &ctx->exec_out[ worker_idx ];

    fd_runtime_public_hash_bank_msg_t * hash_msg = (fd_runtime_public_hash_bank_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
    generate_hash_bank_msg( task_infos_gaddr, lt_hash_gaddr, start_idx, end_idx, hash_msg );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     exec_out->idx,
                     EXEC_HASH_ACCS_SIG,
                     exec_out->chunk,
                     sizeof(fd_runtime_public_hash_bank_msg_t),
                     0UL,
                     tsorig,
                     tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_runtime_public_hash_bank_msg_t), exec_out->chunk0, exec_out->wmark );
  }

  /* Spins and blocks until all exec tiles are done hashing. */
  for( ;; ) {
    uchar wait_cnt = 0;
    for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
      if( !hash_done[ i ] ) {
        ulong res   = fd_fseq_query( ctx->exec_fseq[ i ] );
        uint  state = fd_exec_fseq_get_state( res );
        if( state==FD_EXEC_STATE_HASH_DONE ) {
          hash_done[ i ] = 1;
        } else {
          wait_cnt++;
        }
      }
    }
    if( !wait_cnt ) {
      break;
    }
  }
}


static void
checkpt( fd_replay_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->slots_replayed_file ) ) fclose( ctx->slots_replayed_file );
  if( FD_UNLIKELY( strcmp( ctx->blockstore_checkpt, "" ) ) ) {
    int rc = fd_wksp_checkpt( ctx->blockstore_wksp, ctx->blockstore_checkpt, 0666, 0, NULL );
    if( rc ) {
      FD_LOG_ERR( ( "blockstore checkpt failed: error %d", rc ) );
    }
  }
  int rc = fd_wksp_checkpt( ctx->funk_wksp, ctx->funk_checkpt, 0666, 0, NULL );
  if( rc ) {
    FD_LOG_ERR( ( "funk checkpt failed: error %d", rc ) );
  }
}

static void FD_FN_UNUSED
funk_cancel( fd_replay_tile_ctx_t * ctx, ulong mismatch_slot ) {
  fd_funk_txn_start_write( ctx->funk );
  fd_funk_txn_xid_t   xid          = { .ul = { mismatch_slot, mismatch_slot } };
  fd_funk_txn_map_t * txn_map      = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_t *     mismatch_txn = fd_funk_txn_query( &xid, txn_map );
  FD_TEST( fd_funk_txn_cancel( ctx->funk, mismatch_txn, 1 ) );
  fd_funk_txn_end_write( ctx->funk );
}

static void
txncache_publish( fd_replay_tile_ctx_t * ctx,
                  fd_funk_txn_t *        to_root_txn,
                  fd_funk_txn_t *        rooted_txn ) {


  /* For the status cache, we stop rooting until the status cache has been
     written out to the current snapshot. We also need to iterate up the
     funk transaction tree up until the current "root" to figure out what slots
     should be registered. This root can correspond to the latest false root if
     one exists.  */


  if( FD_UNLIKELY( !ctx->slot_ctx->status_cache ) ) {
    return;
  }

  fd_funk_txn_start_read( ctx->funk );

  fd_funk_txn_t * txn = to_root_txn;
  fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( ctx->funk );
  while( txn!=rooted_txn ) {
    ulong slot = txn->xid.ul[0];
    if( FD_LIKELY( !fd_txncache_get_is_constipated( ctx->slot_ctx->status_cache ) ) ) {
      FD_LOG_INFO(( "Registering slot %lu", slot ));
      fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, slot );
    } else {
      FD_LOG_INFO(( "Registering constipated slot %lu", slot ));
      fd_txncache_register_constipated_slot( ctx->slot_ctx->status_cache, slot );
    }
    txn = fd_funk_txn_parent( txn, txn_pool );
  }

  fd_funk_txn_end_read( ctx->funk );
}

/* NOTE: Snapshot creation is currently not supported in Firedancer V1. We may add support
         for this back in, after the initial release. For that reason, we want to keep around
         the snapshot code, but we return early in this function so that snapshot creation
         is never initiated. */
static void
snapshot_state_update( fd_replay_tile_ctx_t * ctx, ulong wmk ) {

  /* We are ready for a snapshot if either we are on or just passed a snapshot
     interval and no snapshot is currently in progress. This is to handle the
     case where the snapshot interval falls on a skipped slot.

     We are ready to create a snapshot if:
     1. The node is caught up to the network.
     2. There is currently no snapshot in progress
     3. The current slot is at the snapshot interval OR
        The current slot has passed a snapshot interval

    If a snapshot is ready to be created we will constipate funk and the
    status cache. This will also notify the status cache via the funk
    constipation fseq. */

  if( ctx->snapshot_interval==ULONG_MAX ) {
    return;
  }

  uchar is_constipated = fd_fseq_query( ctx->is_constipated ) != 0UL;

  if( !ctx->is_caught_up ) {
    return;
  }

  if( is_constipated ) {
    return;
  }

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );

  /* The distance from the last snapshot should only grow until we skip
     past the last full snapshot. If it has shrunk that means we skipped
     over the snapshot interval. */
  ulong curr_full_snapshot_dist = wmk % ctx->snapshot_interval;
  uchar is_full_snapshot_ready  = curr_full_snapshot_dist < ctx->prev_full_snapshot_dist;
  ctx->prev_full_snapshot_dist  = curr_full_snapshot_dist;

  /* Do the same for incrementals, only try to create one if there has been
     a full snapshot. */

  ulong curr_incr_snapshot_dist = wmk % ctx->incremental_interval;

  uchar is_inc_snapshot_ready   = wmk % ctx->incremental_interval < ctx->prev_incr_snapshot_dist && ctx->last_full_snap;
  ctx->prev_incr_snapshot_dist  = curr_incr_snapshot_dist;

  ulong updated_fseq = 0UL;

  /* TODO: We need a better check if the wmk fell on an epoch boundary due to
     skipped slots. We just don't want to make a snapshot on an epoch boundary */
  if( (is_full_snapshot_ready || is_inc_snapshot_ready) &&
      !fd_runtime_is_epoch_boundary( epoch_bank, wmk, wmk-1UL ) ) {

    /* NOTE: returning early to avoid triggering snapshot creation, as this is not yet supported.*/
    FD_LOG_WARNING(( "snapshot creation not supported! skipping snapshot creation" ));
    return;

    /* Constipate the status cache when a snapshot is ready to be created. */
    if( is_full_snapshot_ready ) {
      ctx->last_full_snap = wmk;
      FD_LOG_NOTICE(( "Ready to create a full snapshot" ));
      updated_fseq = fd_batch_fseq_pack( 1, 0, wmk );
    } else {
      FD_LOG_NOTICE(( "Ready to create an incremental snapshot" ));
      updated_fseq = fd_batch_fseq_pack( 1, 1, wmk );
    }
    fd_txncache_set_is_constipated( ctx->slot_ctx->status_cache, 1 );
    fd_fseq_update( ctx->is_constipated, updated_fseq );
  }
}

static void
funk_publish( fd_replay_tile_ctx_t * ctx,
              fd_funk_txn_t *        to_root_txn,
              ulong                  wmk,
              uchar                  is_constipated ) {

  fd_funk_txn_start_write( ctx->funk );

  fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( ctx->funk );

  /* Try to publish into Funk */
  if( is_constipated ) {
    FD_LOG_NOTICE(( "Publishing slot=%lu while constipated", wmk ));

    /* At this point, first collapse the current transaction that should be
       published into the oldest child transaction. */
    FD_LOG_NOTICE(( "Publishing into constipated root for wmk=%lu", wmk ));
    fd_funk_txn_t * txn        = to_root_txn;

    while( txn!=ctx->false_root ) {
      if( FD_UNLIKELY( fd_funk_txn_publish_into_parent( ctx->funk, txn, 0 ) ) ) {
        FD_LOG_ERR(( "Can't publish funk transaction" ));
      }
      txn = fd_funk_txn_parent( txn, txn_pool );
    }

  } else {
    /* This is the case where we are not in the constipated case. We only need
       to do special handling in the case where the epoch account hash is about
       to be calculated. */
    FD_LOG_NOTICE(( "Publishing slot=%lu xid=%lu", wmk, to_root_txn->xid.ul[0] ));

    /* This is the standard case. Publish all transactions up to and
       including the watermark. This will publish any in-prep ancestors
       of root_txn as well. */
    if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, to_root_txn, 1 ) ) ) {
      FD_LOG_ERR(( "failed to funk publish slot %lu", wmk ));
    }
  }
  fd_funk_txn_end_write( ctx->funk );

  if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx->slot_ctx->slot_bank.slot, ctx->slot_ctx->epoch_ctx->features, epoch_accounts_hash ) && !FD_FEATURE_ACTIVE( ctx->slot_ctx->slot_bank.slot, ctx->slot_ctx->epoch_ctx->features, accounts_lt_hash ) ) ) {
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
    if( wmk>=epoch_bank->eah_start_slot ) {
      fd_exec_para_cb_ctx_t exec_para_ctx = {
        .func       = fd_accounts_hash_counter_and_gather_tpool_cb,
        .para_arg_1 = NULL,
        .para_arg_2 = NULL
      };

      fd_accounts_hash( ctx->slot_ctx->funk,
                        &ctx->slot_ctx->slot_bank,
                        &ctx->slot_ctx->slot_bank.epoch_account_hash,
                        ctx->runtime_spad,
                        &ctx->slot_ctx->epoch_ctx->features,
                        &exec_para_ctx,
                        NULL );
      FD_LOG_NOTICE(( "Done computing epoch account hash (%s)", FD_BASE58_ENC_32_ALLOCA( &ctx->slot_ctx->slot_bank.epoch_account_hash ) ));
      epoch_bank->eah_start_slot = FD_SLOT_NULL;
    }
  }

}

static fd_funk_txn_t*
get_rooted_txn( fd_replay_tile_ctx_t * ctx,
                fd_funk_txn_t *     to_root_txn,
                uchar                  is_constipated ) {

  /* We need to get the rooted transaction that we are publishing into. This
     needs to account for the two different cases: no constipation and single
     constipation.

     Also, if it's the first time that we are setting the false root, then
     we must also register it into the status cache because we don't register
     the root in txncache_publish to avoid registering the same slot multiple times. */

  fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( ctx->funk );

  if( is_constipated ) {

    if( FD_UNLIKELY( !ctx->false_root ) ) {

      fd_funk_txn_t * txn        = to_root_txn;
      fd_funk_txn_t * parent_txn = fd_funk_txn_parent( txn, txn_pool );
      while( parent_txn ) {
        txn        = parent_txn;
        parent_txn = fd_funk_txn_parent( txn, txn_pool );
      }

      ctx->false_root = txn;
      if( !fd_txncache_get_is_constipated( ctx->slot_ctx->status_cache ) ) {
        fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      } else {
        fd_txncache_register_constipated_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      }
    }
    return ctx->false_root;
  } else {
    return NULL;
  }
}

static void
funk_and_txncache_publish( fd_replay_tile_ctx_t * ctx, ulong wmk, fd_funk_txn_xid_t const * xid ) {

  FD_LOG_NOTICE(( "Entering funk_and_txncache_publish for wmk=%lu", wmk ));

  /* This function is responsible for publishing/registering all in-prep slots
     up to and including the watermark slot into funk and the transaction cache.

     However, we need to modify this behavior to support snapshot creation and
     epoch account hash generation (which is handled by the batch tile).
     Specifically, we need to change the mechanism by introducing the concept of
     a constipated root. We want to keep the root of funk/txncache constant
     while the batch tile reads from the root of funk. At the same time, we
     want to keep publishing into funk. We accomplish this by treating the
     oldest in-prep ancestor of funk as the "constipated/false" root. While
     the batch tile "works", we will only publish into the false root. Once the
     batch tile is done producing a snapshot/eah, we will then flush the
     constipated root into the real root of funk as we no longer need a frozen
     funk transaction to read from. The batch tile will communicate with the
     replay tile via the is_constipated fseq and a link.

     A similar mechanism for txncache constipation is needed only for snapshot
     creation. This is simpler than for funk because txncache operations are
     atomic and we can just register slots into a constipated set while the
     txncache is getting copied out. This is a much faster operation and the
     txncache will likely get unconstipated before funk.

     Single Funk Constipation Example:

     If we want to create a snapshot/eah for slot n, then we will publish
     all transactions up to and including those that correspond to slot n.
     We will then publish all transactions into the immediate child of n (lets
     assume it's n+1) in this case. So every transaction will be published into
     n+1 and NOT n. When the computation is done, we resume publishing as normal.
  */

  uchar is_constipated = fd_fseq_query( ctx->is_constipated ) != 0;

  /* If the false root is no longer needed, then we should stop
     tracking it. */

  if( FD_UNLIKELY( ctx->false_root && !is_constipated ) ) {
    FD_LOG_NOTICE(( "Unsetting false root tracking" ));
    ctx->false_root = NULL;
  }

  /* Handle updates to funk and the status cache. */

  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_map_t * txn_map     = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_t *     to_root_txn = fd_funk_txn_query( xid, txn_map );
  if( FD_UNLIKELY( !to_root_txn ) ) {
    FD_LOG_ERR(( "Unable to find funk transaction for xid %lu", xid->ul[0] ));
  }
  fd_funk_txn_t *   rooted_txn  = get_rooted_txn( ctx, to_root_txn, is_constipated );
  fd_funk_txn_end_read( ctx->funk );

  txncache_publish( ctx, to_root_txn, rooted_txn );

  funk_publish( ctx, to_root_txn, wmk, is_constipated );

  /* Update the snapshot state and determine if one is ready to be created. */

  snapshot_state_update( ctx, wmk );

  if( FD_UNLIKELY( ctx->capture_ctx ) ) {
    fd_runtime_checkpt( ctx->capture_ctx, ctx->slot_ctx, wmk );
  }

}

static void
replay_plugin_publish( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t * stem,
                       ulong sig,
                       uchar const * data,
                       ulong data_sz ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->plugin_out->mem, ctx->plugin_out->chunk );
  fd_memcpy( dst, data, data_sz );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->plugin_out->idx, sig, ctx->plugin_out->chunk, data_sz, 0UL, 0UL, tspub );
  ctx->plugin_out->chunk = fd_dcache_compact_next( ctx->plugin_out->chunk, data_sz, ctx->plugin_out->chunk0, ctx->plugin_out->wmark );
}

static void
publish_slot_notifications( fd_replay_tile_ctx_t * ctx,
                            fd_stem_context_t *    stem,
                            fd_fork_t *            fork,
                            ulong                  block_entry_block_height,
                            ulong                  curr_slot ) {
  if( FD_LIKELY( !ctx->notif_out->mcache ) ) return;

  long notify_time_ns = -fd_log_wallclock();
#define NOTIFY_START msg = fd_chunk_to_laddr( ctx->notif_out->mem, ctx->notif_out->chunk )
#define NOTIFY_END                                                      \
  fd_mcache_publish( ctx->notif_out->mcache, ctx->notif_out->depth, ctx->notif_out->seq, \
                      0UL, ctx->notif_out->chunk, sizeof(fd_replay_notif_msg_t), 0UL, tsorig, tsorig ); \
  ctx->notif_out->seq   = fd_seq_inc( ctx->notif_out->seq, 1UL );     \
  ctx->notif_out->chunk = fd_dcache_compact_next( ctx->notif_out->chunk, sizeof(fd_replay_notif_msg_t), \
                                                  ctx->notif_out->chunk0, ctx->notif_out->wmark ); \
  msg = NULL

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_replay_notif_msg_t * msg = NULL;

  FD_LOG_NOTICE(( "shred cnt %lu %lu", curr_slot, fork->slot_ctx->shred_cnt ));
  {
    NOTIFY_START;
    msg->type = FD_REPLAY_SLOT_TYPE;
    msg->slot_exec.slot = curr_slot;
    msg->slot_exec.parent = ctx->parent_slot;
    msg->slot_exec.root = fd_fseq_query( ctx->published_wmark );
    msg->slot_exec.height = block_entry_block_height;
    msg->slot_exec.transaction_count = fork->slot_ctx->slot_bank.transaction_count;
    msg->slot_exec.shred_cnt = fork->slot_ctx->shred_cnt;
    msg->slot_exec.bank_hash = fork->slot_ctx->slot_bank.banks_hash;
    memcpy( &msg->slot_exec.identity, ctx->validator_identity_pubkey, sizeof( fd_pubkey_t ) );
    msg->slot_exec.ts = tsorig;
    NOTIFY_END;
  }
  fork->slot_ctx->shred_cnt = 0UL;

#undef NOTIFY_START
#undef NOTIFY_END
  notify_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: notify_slot_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)notify_time_ns * 1e-6));

  if( ctx->plugin_out->mem ) {
    /*
    fd_replay_complete_msg_t msg2 = {
      .slot = curr_slot,
      .total_txn_count = fork->slot_ctx->txn_count,
      .nonvote_txn_count = fork->slot_ctx->nonvote_txn_count,
      .failed_txn_count = fork->slot_ctx->failed_txn_count,
      .nonvote_failed_txn_count = fork->slot_ctx->nonvote_failed_txn_count,
      .compute_units = fork->slot_ctx->total_compute_units_used,
      .transaction_fee = fork->slot_ctx->slot_bank.collected_execution_fees,
      .priority_fee = fork->slot_ctx-2842>slot_bank.collected_priority_fees,
      .parent_slot = ctx->parent_slot,
    };
    */
    ulong msg[11];
    msg[ 0 ] = ctx->curr_slot;
    msg[ 1 ] = fork->slot_ctx->txn_count;
    msg[ 2 ] = fork->slot_ctx->nonvote_txn_count;
    msg[ 3 ] = fork->slot_ctx->failed_txn_count;
    msg[ 4 ] = fork->slot_ctx->nonvote_failed_txn_count;
    msg[ 5 ] = fork->slot_ctx->total_compute_units_used;
    msg[ 6 ] = fork->slot_ctx->slot_bank.collected_execution_fees;
    msg[ 7 ] = fork->slot_ctx->slot_bank.collected_priority_fees;
    msg[ 8 ] = 0UL; /* todo ... track tips */
    msg[ 9 ] = ctx->parent_slot;
    msg[ 10 ] = 0UL;  /* todo ... max compute units */
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_COMPLETED, (uchar const *)msg, sizeof(msg) );
  }
}

static void
send_tower_sync( fd_replay_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->vote ) ) return;
  FD_LOG_NOTICE( ( "sending tower sync" ) );
  ulong vote_slot = fd_tower_votes_peek_tail_const( ctx->tower )->slot;
  fd_hash_t vote_bank_hash[1]  = { 0 };
  fd_hash_t vote_block_hash[1] = { 0 };
  int err = fd_blockstore_bank_hash_query( ctx->blockstore, vote_slot, vote_bank_hash );
  if( err ) FD_LOG_ERR(( "invariant violation: missing bank hash for tower vote" ));
  err = fd_blockstore_block_hash_query( ctx->blockstore, vote_slot, vote_block_hash );
  if( err ) FD_LOG_ERR(( "invariant violation: missing block hash for tower vote" ));

  /* Build a vote state update based on current tower votes. */

  fd_txn_p_t * txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->sender_out->mem, ctx->sender_out->chunk );
  fd_tower_to_vote_txn( ctx->tower,
                        ctx->root,
                        vote_bank_hash,
                        vote_block_hash,
                        ctx->validator_identity,
                        ctx->vote_authority,
                        ctx->vote_acc,
                        txn,
                        ctx->runtime_spad );

  /* TODO: Can use a smaller size, adjusted for payload length */
  ulong msg_sz     = sizeof( fd_txn_p_t );
  fd_mcache_publish( ctx->sender_out->mcache,
                     ctx->sender_out->depth,
                     ctx->sender_out->seq,
                     1UL,
                     ctx->sender_out->chunk,
                     msg_sz,
                     0UL,
                     0,
                     0 );
  ctx->sender_out->seq   = fd_seq_inc( ctx->sender_out->seq, 1UL );
  ctx->sender_out->chunk = fd_dcache_compact_next( ctx->sender_out->chunk,
                                                  msg_sz,
                                                  ctx->sender_out->chunk0,
                                                  ctx->sender_out->wmark );

  /* Dump the latest sent tower into the tower checkpoint file */
  if( FD_LIKELY( ctx->tower_checkpt_fileno > 0 ) ) fd_restart_tower_checkpt( vote_bank_hash, ctx->tower, ctx->ghost, ctx->root, ctx->tower_checkpt_fileno );
}

static void
send_exec_epoch_msg( fd_replay_tile_ctx_t * ctx,
                     fd_stem_context_t *    stem,
                     fd_exec_slot_ctx_t *   slot_ctx ) {

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    ctx->exec_ready[ i ] = EXEC_EPOCH_WAIT;
    fd_replay_out_link_t * exec_out = &ctx->exec_out[ i ];

    fd_runtime_public_epoch_msg_t * epoch_msg = (fd_runtime_public_epoch_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );

    generate_replay_exec_epoch_msg( slot_ctx,
                                    ctx->runtime_spad,
                                    ctx->runtime_public_wksp,
                                    ctx->bank_hash_cmp,
                                    epoch_msg );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     exec_out->idx,
                     EXEC_NEW_EPOCH_SIG,
                     exec_out->chunk,
                     sizeof(fd_runtime_public_epoch_msg_t),
                     0UL,
                     tsorig, tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_runtime_public_epoch_msg_t), exec_out->chunk0, exec_out->wmark );
  }
}

static void
send_exec_slot_msg( fd_replay_tile_ctx_t * ctx,
                    fd_stem_context_t *    stem,
                    fd_exec_slot_ctx_t *   slot_ctx ) {

  /* At this point we need to notify all of the exec tiles and tell them
     that a new slot is ready to be published. At this point, we should
     also mark the tile as not not being ready. */

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    ctx->exec_ready[ i ]            = EXEC_SLOT_WAIT;
    fd_replay_out_link_t * exec_out = &ctx->exec_out[ i ];

    fd_runtime_public_slot_msg_t * slot_msg = (fd_runtime_public_slot_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
    generate_replay_exec_slot_msg( slot_ctx, ctx->runtime_spad, ctx->runtime_public_wksp, slot_msg );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     exec_out->idx,
                     EXEC_NEW_SLOT_SIG,
                     exec_out->chunk,
                     sizeof(fd_runtime_public_slot_msg_t),
                     0UL,
                     tsorig,
                     tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_runtime_public_slot_msg_t), exec_out->chunk0, exec_out->wmark );
  }

  /* Notify writer tiles as well. */
  for( ulong i=0UL; i<ctx->writer_cnt; i++ ) {
    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    fd_replay_out_link_t * writer_out = &ctx->writer_out[ i ];

    fd_runtime_public_replay_writer_slot_msg_t * slot_msg = (fd_runtime_public_replay_writer_slot_msg_t *)fd_chunk_to_laddr( writer_out->mem, writer_out->chunk );
    slot_msg->slot_ctx_gaddr = fd_wksp_gaddr_fast( ctx->runtime_public_wksp, slot_ctx );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     writer_out->idx,
                     FD_WRITER_SLOT_SIG,
                     writer_out->chunk,
                     sizeof(fd_runtime_public_replay_writer_slot_msg_t),
                     0UL,
                     tsorig,
                     tspub );
    writer_out->chunk = fd_dcache_compact_next( writer_out->chunk, sizeof(fd_runtime_public_replay_writer_slot_msg_t), writer_out->chunk0, writer_out->wmark );
  }
}

static fd_fork_t *
prepare_new_block_execution( fd_replay_tile_ctx_t * ctx,
                             fd_stem_context_t *    stem,
                             ulong                  curr_slot,
                             ulong                  flags ) {

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ctx->exec_ready[ i ] = EXEC_SLOT_WAIT;
  }

  long prepare_time_ns = -fd_log_wallclock();

  int is_new_epoch_in_new_block = 0;
  fd_fork_t * fork = fd_forks_prepare( ctx->forks,
                                       ctx->parent_slot,
                                       ctx->funk,
                                       ctx->blockstore,
                                       ctx->epoch_ctx,
                                       ctx->runtime_spad );

  /* Remove previous slot ctx from frontier */
  fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->forks->frontier, &fork->slot, NULL, ctx->forks->pool );
  child->slot       = curr_slot;
  child->end_idx    = UINT_MAX; // reset end_idx from whatever was previously executed on this fork

  /* Insert new slot onto fork frontier */
  if( FD_UNLIKELY( fd_fork_frontier_ele_query(
      ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool ) ) ) {
    FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", curr_slot ) );
  }
  fd_fork_frontier_ele_insert( ctx->forks->frontier, child, ctx->forks->pool );
  fork->lock = 1;
  FD_TEST( fork == child );

  FD_LOG_NOTICE(( "new block execution - slot: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( fork->slot_ctx->epoch_ctx );

  /* If it is an epoch boundary, push out stake weights */
  if( fork->slot_ctx->slot_bank.slot != 0 ) {
    is_new_epoch_in_new_block = (int)fd_runtime_is_epoch_boundary( epoch_bank, fork->slot_ctx->slot_bank.slot, fork->slot_ctx->slot_bank.prev_slot );
  }

  /* Update starting PoH hash for the new slot for tick verification later */
  fd_block_map_query_t query[1] = { 0 };
  int err = fd_block_map_prepare( ctx->blockstore->block_map, &curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * curr_block_info = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( err == FD_MAP_ERR_FULL ) ) FD_LOG_ERR(("Block map prepare failed, likely corrupt."));
  if( FD_UNLIKELY( curr_slot != curr_block_info->slot ) ) FD_LOG_ERR(("Block map prepare failed, likely corrupt."));
  curr_block_info->in_poh_hash = fork->slot_ctx->slot_bank.poh;
  fd_block_map_publish( query );

  fork->slot_ctx->slot_bank.prev_slot   = fork->slot_ctx->slot_bank.slot;
  fork->slot_ctx->slot_bank.slot        = curr_slot;
  fork->slot_ctx->slot_bank.tick_height = fork->slot_ctx->slot_bank.max_tick_height;
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( epoch_bank->ticks_per_slot, curr_slot, &fork->slot_ctx->slot_bank.max_tick_height ) ) ) {
    FD_LOG_ERR(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", curr_slot, epoch_bank->ticks_per_slot ));
  }
  fork->slot_ctx->enable_exec_recording = ctx->tx_metadata_storage;
  fork->slot_ctx->runtime_wksp          = fd_wksp_containing( ctx->runtime_spad );

  /* NOTE: By commenting this out, we don't support forking at the epoch boundary
     but this code is buggy and leads to crashes. */
  // if( fd_runtime_is_epoch_boundary( epoch_bank, fork->slot_ctx->slot_bank.slot, fork->slot_ctx->slot_bank.prev_slot ) ) {
  //   FD_LOG_WARNING(("Epoch boundary"));

  //   fd_epoch_fork_elem_t * epoch_fork = NULL;
  //   ulong new_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, fork->slot_ctx->slot_bank.slot, NULL );
  //   uint found = fd_epoch_forks_prepare( ctx->epoch_forks, fork->slot_ctx->slot_bank.prev_slot, new_epoch, &epoch_fork );

  //   if( FD_UNLIKELY( found ) ) {
  //     fd_exec_epoch_ctx_bank_mem_clear( epoch_fork->epoch_ctx );
  //   }
  //   fd_exec_epoch_ctx_t * prev_epoch_ctx = fork->slot_ctx->epoch_ctx;

  //   fd_exec_epoch_ctx_from_prev( epoch_fork->epoch_ctx, prev_epoch_ctx, ctx->runtime_spad );
  //   fork->slot_ctx->epoch_ctx = epoch_fork->epoch_ctx;
  // }

  fork->slot_ctx->status_cache = ctx->status_cache;

  fd_funk_txn_xid_t xid = { 0 };

  if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
    memset( xid.uc, 0, sizeof(fd_funk_txn_xid_t) );
  } else {
    xid.ul[1] = fork->slot_ctx->slot_bank.slot;
  }
  xid.ul[0] = fork->slot_ctx->slot_bank.slot;
  /* push a new transaction on the stack */
  fd_funk_txn_start_write( ctx->funk );
  fork->slot_ctx->funk_txn = fd_funk_txn_prepare(ctx->funk, fork->slot_ctx->funk_txn, &xid, 1);
  fd_funk_txn_end_write( ctx->funk );

  /* We must invalidate all of the sysvar cache entries in the case that
     their memory is no longer valid/the cache contains stale data. */
  fd_sysvar_cache_invalidate( fork->slot_ctx->sysvar_cache );

  int is_epoch_boundary = 0;
  /* TODO: Currently all of the epoch boundary/rewards logic is not
     multhreaded at the epoch boundary. */
  fd_runtime_block_pre_execute_process_new_epoch( fork->slot_ctx,
                                                  NULL,
                                                  ctx->exec_spads,
                                                  ctx->exec_spad_cnt,
                                                  ctx->runtime_spad,
                                                  &is_epoch_boundary );

  if( FD_UNLIKELY( is_epoch_boundary ) ) {
    send_exec_epoch_msg( ctx, stem, fork->slot_ctx );
  }

  /* At this point we need to notify all of the exec tiles and tell them
     that a new slot is ready to be published. At this point, we should
     also mark the tile as not being ready. */
  send_exec_slot_msg( ctx, stem, fork->slot_ctx );

  /* We want to push on a spad frame before we start executing a block.
     Apart from allocations made at the epoch boundary, there should be no
     allocations that persist beyond the scope of a block. Before this point,
     there should only be 1 or 2 frames that are on the stack. The first frame
     will hold memory for the slot/epoch context. The potential second frame
     will only exist while rewards are being distributed (around the start of
     an epoch). We pop a frame when rewards are done being distributed. */
  fd_spad_push( ctx->runtime_spad );

  int res = fd_runtime_block_execute_prepare( fork->slot_ctx, ctx->runtime_spad );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "block prep execute failed" ));
  }

  /* Read slot history into slot ctx */
  fork->slot_ctx->slot_history = fd_sysvar_cache_slot_history( fork->slot_ctx->sysvar_cache,
                                                               fork->slot_ctx->runtime_wksp );

  if( is_new_epoch_in_new_block ) {
    publish_stake_weights( ctx, stem, fork->slot_ctx );
  }

  prepare_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: prepare_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)prepare_time_ns * 1e-6));

  return fork;
}

static void
init_poh( fd_replay_tile_ctx_t * ctx ) {
  FD_LOG_INFO(( "sending init msg" ));
  fd_replay_out_link_t * bank_out = &ctx->bank_out[ 0UL ];
  fd_poh_init_msg_t * msg = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->epoch_ctx );
  msg->hashcnt_per_tick = ctx->epoch_ctx->epoch_bank.hashes_per_tick;
  msg->ticks_per_slot   = ctx->epoch_ctx->epoch_bank.ticks_per_slot;
  msg->tick_duration_ns = (ulong)(epoch_bank->ns_per_slot / epoch_bank->ticks_per_slot);
  if( ctx->slot_ctx->slot_bank.block_hash_queue.last_hash ) {
    memcpy(msg->last_entry_hash, ctx->slot_ctx->slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t));
  } else {
    memset(msg->last_entry_hash, 0UL, sizeof(fd_hash_t));
  }
  msg->tick_height = ctx->slot_ctx->slot_bank.slot * msg->ticks_per_slot;

  ulong sig = fd_disco_replay_old_sig( ctx->slot_ctx->slot_bank.slot, REPLAY_FLAG_INIT );
  fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, sizeof(fd_poh_init_msg_t), 0UL, 0UL, 0UL );
  bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, sizeof(fd_poh_init_msg_t), bank_out->chunk0, bank_out->wmark );
  bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  ctx->poh_init_done = 1;
}

static void
prepare_first_batch_execution( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {

  ulong curr_slot   = ctx->curr_slot;
  ulong flags       = ctx->flags;

  /**********************************************************************/
  /* Get the epoch_ctx for replaying curr_slot                          */
  /**********************************************************************/

  ulong epoch_ctx_idx = fd_epoch_forks_get_epoch_ctx( ctx->epoch_forks, ctx->ghost, curr_slot, &ctx->parent_slot );
  ctx->epoch_ctx = ctx->epoch_forks->forks[ epoch_ctx_idx ].epoch_ctx;

  /**********************************************************************/
  /* Prepare the fork in ctx->forks for replaying curr_slot             */
  /**********************************************************************/

  fd_fork_t * parent_fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->parent_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( parent_fork && parent_fork->lock ) ) {
    /* This is an edge case related to pack. The parent fork might
       already be in the frontier and currently executing (ie.
       fork->frozen = 0). */
    FD_LOG_ERR(( "parent slot is frozen in frontier. cannot execute. slot: %lu, parent_slot: %lu",
                 curr_slot,
                 ctx->parent_slot ));
  }

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );
  if( fork==NULL ) {
    fork = prepare_new_block_execution( ctx, stem, curr_slot, flags );
  } else {
    FD_LOG_WARNING(("Fork for slot %lu already exists, so we don't make a new one. Restarting execution from batch %u", curr_slot, fork->end_idx ));
  }
  ctx->slot_ctx = fork->slot_ctx;

  /**********************************************************************/
  /* Get the solcap context for replaying curr_slot                     */
  /**********************************************************************/

  if( ctx->capture_ctx ) {
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx->slot_bank.slot );
  }

}

static void
exec_slice( fd_replay_tile_ctx_t * ctx,
             fd_stem_context_t *   stem,
             ulong                 slot ) {

  /* Assumes that the slice exec ctx has buffered at least one slice.
     Then, for each microblock, round robin dispatch the transactions in
     that microblock to the exec tile. Once exec tile signifies with a
     retcode, we can continue dispatching transactions. Replay has to
     synchronize at the boundary of every microblock. After we dispatch
     one to each exec tile, we watermark where we are, and then continue
     on the following after_credit. If we still have txns to execute,
     start from wmark, pausing everytime we hit the microblock
     boundaries. */

  uchar to_exec[ FD_PACK_MAX_BANK_TILES ];
  uchar num_free_exec_tiles = 0UL;
  for( uchar i=0; i<ctx->exec_cnt; i++ ) {
    if( ctx->exec_ready[ i ]==EXEC_TXN_READY ) {
      to_exec[ num_free_exec_tiles++ ] = i;
    }
  }

  if( ctx->blocked_on_mblock ) {
    if( num_free_exec_tiles==ctx->exec_cnt ) {
      ctx->blocked_on_mblock = 0;
    } else {
      return;
    }
  }

  uchar start_num_free_exec_tiles = (uchar)ctx->exec_cnt;
  while( num_free_exec_tiles>0 ) {

    if( fd_slice_exec_txn_ready( &ctx->slice_exec_ctx ) ) {
      ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

      uchar                  exec_idx = to_exec[ num_free_exec_tiles-1 ];
      fd_replay_out_link_t * exec_out = &ctx->exec_out[ exec_idx ];
      num_free_exec_tiles--;

      fd_txn_p_t txn_p;
      fd_slice_exec_txn_parse( &ctx->slice_exec_ctx, &txn_p );

      fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier,
                                                     &slot,
                                                     NULL,
                                                     ctx->forks->pool );

      if( FD_UNLIKELY( !fork ) ) FD_LOG_ERR(( "Unable to select a fork" ));

      fork->slot_ctx->txn_count++;

      /* dispatch dcache */
      fd_runtime_public_txn_msg_t * exec_msg = (fd_runtime_public_txn_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      memcpy( &exec_msg->txn, &txn_p, sizeof(fd_txn_p_t) );

      ctx->exec_ready[ exec_idx ] = EXEC_TXN_BUSY;
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, exec_out->idx, EXEC_NEW_TXN_SIG, exec_out->chunk, sizeof(fd_runtime_public_txn_msg_t), 0UL, tsorig, tspub );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_runtime_public_txn_msg_t), exec_out->chunk0, exec_out->wmark );

      continue;
    }

    /* If the current microblock is complete, and we still have mblks
       to read, then advance to the next microblock */

    if( fd_slice_exec_microblock_ready( &ctx->slice_exec_ctx ) ) {
      ctx->blocked_on_mblock = 1;
      fd_slice_exec_microblock_parse( &ctx->slice_exec_ctx );
    }

    /* Under this condition, we have finished executing all the
       microblocks in the slice, and are ready to load another slice.
       However, if just completed the last batch in the slot, we want
       to be sure to finalize block execution (below). */

    if( fd_slice_exec_slice_ready( &ctx->slice_exec_ctx )
        && !ctx->slice_exec_ctx.last_batch ){
      ctx->flags = EXEC_FLAG_READY_NEW;
    }
    break; /* block on microblock / batch */
  }

  if( fd_slice_exec_slot_complete( &ctx->slice_exec_ctx ) ) {

    if( num_free_exec_tiles != start_num_free_exec_tiles ) {
      FD_LOG_DEBUG(( "blocked on exec tiles completing" ));
      return;
    }

    FD_LOG_DEBUG(( "[%s] BLOCK EXECUTION COMPLETE", __func__ ));

     /* At this point, the entire block has been executed. */
    fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier,
                                                    &slot,
                                                    NULL,
                                                    ctx->forks->pool );
    if( FD_UNLIKELY( !fork ) ) {
      FD_LOG_ERR(( "Unable to select a fork" ));
    }

    fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( ctx->slice_exec_ctx.mbatch + ctx->slice_exec_ctx.last_mblk_off );

    // Copy block hash to slot_bank poh for updating the sysvars
    fd_block_map_query_t query[1] = { 0 };
    fd_block_map_prepare( ctx->blockstore->block_map, &ctx->curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );

    memcpy( fork->slot_ctx->slot_bank.poh.uc, hdr->hash, sizeof(fd_hash_t) );
    block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_PROCESSED );
    FD_COMPILER_MFENCE();
    block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
    memcpy( &block_info->block_hash, hdr->hash, sizeof(fd_hash_t) );
    block_info->bank_hash = fork->slot_ctx->slot_bank.banks_hash;

    fd_block_map_publish( query );
    ctx->flags = EXEC_FLAG_FINISHED_SLOT;

    fd_slice_exec_reset( &ctx->slice_exec_ctx ); /* Reset ctx for next slot */
  }

}

/* handle_slice polls for a new slice off the slices stored in the
   deque, and prepares it for execution, including call
   prepare_first_batch_execution if this is the first slice of a new
   slot. Also queries blockstore for the corresponding shreds and stores
   them into the slice_exec_ctx. Assumes that replay is ready for a new
   slice (i.e., finished executing the previous slice). */
static void
handle_slice( fd_replay_tile_ctx_t * ctx,
              fd_stem_context_t *    stem ) {

  if( fd_exec_slice_cnt( ctx->exec_slice_deque )==0UL ) {
    FD_LOG_DEBUG(( "No slices to execute" ));
    return;
  }

  ulong sig = fd_exec_slice_pop_head( ctx->exec_slice_deque );

  if( FD_UNLIKELY( ctx->flags!=EXEC_FLAG_READY_NEW ) ) {
    FD_LOG_ERR(( "Replay is in unexpected state" ));
  }

  ulong  slot          = fd_disco_repair_replay_sig_slot( sig );
  ushort parent_off    = fd_disco_repair_replay_sig_parent_off( sig );
  uint   data_cnt      = fd_disco_repair_replay_sig_data_cnt( sig );
  int    slot_complete = fd_disco_repair_replay_sig_slot_complete( sig );
  ulong  parent_slot   = slot - parent_off;

  if( FD_UNLIKELY( slot < fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). earlier than our watermark %lu.", slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ));
    return;
  }

  if( FD_UNLIKELY( parent_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). parent slot is earlier than our watermark %lu.", slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ) );
    return;
  }

  if( FD_UNLIKELY( !fd_blockstore_block_info_test( ctx->blockstore, parent_slot ) ) ) {
    FD_LOG_WARNING(( "unable to find slot %lu's parent slot %lu block_info", slot, parent_slot ));
    return;
  }

  if( FD_UNLIKELY( slot != ctx->curr_slot ) ) {

    /* We need to switch forks and execution contexts. Either we
        completed execution of the previous slot and are now executing
        a new slot or we are interleaving batches from different slots
        - all executable at the fork frontier.

        Going to need to query the frontier for the fork, or create it
        if its not on the frontier. I think
        prepare_first_batch_execution already handles this logic. */

    ctx->curr_slot   = slot;
    ctx->parent_slot = parent_slot;
    prepare_first_batch_execution( ctx, stem );

    ulong curr_turbine_slot = fd_fseq_query( ctx->curr_turbine_slot );

    FD_LOG_NOTICE( ( "\n\n[Replay]\n"
      "slot:            %lu\n"
      "current turbine: %lu\n"
      "slots behind:    %lu\n"
      "live:            %d\n",
      slot,
      curr_turbine_slot,
      curr_turbine_slot - slot,
      ( curr_turbine_slot - slot ) < 5 ) );
  } else {
    /* continuing execution of the slot we have been doing */
  }

  /* Prepare batch for execution on following after_credit iteration */
  ctx->flags = EXEC_FLAG_EXECUTING_SLICE;
  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &slot, NULL, ctx->forks->pool );
  ulong slice_sz;
  uint start_idx = fork->end_idx + 1;
  int err = fd_blockstore_slice_query( ctx->slot_ctx->blockstore,
                                        slot,
                                        start_idx,
                                        start_idx + data_cnt - 1,
                                        FD_SLICE_MAX,
                                        ctx->slice_exec_ctx.mbatch,
                                        &slice_sz );
  fork->end_idx += data_cnt;
  fd_slice_exec_begin( &ctx->slice_exec_ctx, slice_sz, slot_complete );
  fork->slot_ctx->shred_cnt += data_cnt;

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to query blockstore for slot %lu", slot ));
  }
}

static void
kickoff_repair_orphans( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {

  fd_blockstore_init( ctx->slot_ctx->blockstore, ctx->blockstore_fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &ctx->slot_ctx->slot_bank );

  fd_fseq_update( ctx->published_wmark, ctx->slot_ctx->slot_bank.slot );
  publish_stake_weights( ctx, stem, ctx->slot_ctx );

}

static void
read_snapshot( void *              _ctx,
               fd_stem_context_t * stem,
               char const *        snapshot,
               char const *        incremental,
               char const *        snapshot_dir ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  fd_exec_para_cb_ctx_t exec_para_ctx_snap = {
    .func       = snapshot_hash_tiles_cb,
    .para_arg_1 = ctx,
    .para_arg_2 = stem,
  };

  /* Pass the slot_ctx to snapshot_load or recover_banks */
  /* Base slot is the slot we will compare against the base slot of the incremental snapshot, to ensure that the
     base slot of the incremental snapshot is the slot of the full snapshot.

     We pull this out of the full snapshot to use when verifying the incremental snapshot. */
  ulong        base_slot = 0UL;
  if( strcmp( snapshot, "funk" )==0 || strncmp( snapshot, "wksp:", 5 )==0 ) {
    /* Funk already has a snapshot loaded */
    fd_runtime_recover_banks( ctx->slot_ctx, 1, 1, ctx->runtime_spad );
    base_slot = ctx->slot_ctx->slot_bank.slot;
    kickoff_repair_orphans( ctx, stem );
  } else {

    /* If we have an incremental snapshot try to prefetch the snapshot slot
       and manifest as soon as possible. In order to kick off repair effectively
       we need the snapshot slot and the stake weights. These are both available
       in the manifest. We will try to load in the manifest from the latest
       snapshot that is availble, then setup the blockstore and publish the
       stake weights. After this, repair will kick off concurrently with loading
       the rest of the snapshots. */

    /* TODO: Verify account hashes for all 3 snapshot loads. */
    /* TODO: If prefetching the manifest is enabled it leads to
       incorrect snapshot loads. This needs to be looked into. */
    if( strlen( incremental )>0UL ) {
      uchar * tmp_mem = fd_spad_alloc_check( ctx->runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );

      fd_snapshot_load_ctx_t * tmp_snap_ctx = fd_snapshot_load_new( tmp_mem,
                                                                    incremental,
                                                                    ctx->incremental_src_type,
                                                                    NULL,
                                                                    ctx->slot_ctx,
                                                                    false,
                                                                    false,
                                                                    FD_SNAPSHOT_TYPE_INCREMENTAL,
                                                                    ctx->exec_spads,
                                                                    ctx->exec_spad_cnt,
                                                                    ctx->runtime_spad,
                                                                    &exec_para_ctx_snap );
      /* Load the prefetch manifest, and initialize the status cache and slot context,
         so that we can use these to kick off repair. */
      fd_snapshot_load_prefetch_manifest( tmp_snap_ctx );
      kickoff_repair_orphans( ctx, stem );

    }

    uchar *                  mem      = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
    fd_snapshot_load_ctx_t * snap_ctx = fd_snapshot_load_new( mem,
                                                              snapshot,
                                                              ctx->snapshot_src_type,
                                                              snapshot_dir,
                                                              ctx->slot_ctx,
                                                              false,
                                                              false,
                                                              FD_SNAPSHOT_TYPE_FULL,
                                                              ctx->exec_spads,
                                                              ctx->exec_spad_cnt,
                                                              ctx->runtime_spad,
                                                              &exec_para_ctx_snap );

    fd_snapshot_load_init( snap_ctx );

    /* If we don't have an incremental snapshot, load the manifest and the status cache and initialize
         the objects because we don't have these from the incremental snapshot. */
    if( strlen( incremental )<=0UL ) {
      fd_snapshot_load_manifest_and_status_cache( snap_ctx, NULL,
        FD_SNAPSHOT_RESTORE_MANIFEST | FD_SNAPSHOT_RESTORE_STATUS_CACHE );

      kickoff_repair_orphans( ctx, stem );
      /* If we don't have an incremental snapshot, we can still kick off
         sending the stake weights and snapshot slot to repair. */
    } else {
      /* If we have an incremental snapshot, load the manifest and the status cache,
          and don't initialize the objects because we did this above from the incremental snapshot. */
      fd_snapshot_load_manifest_and_status_cache( snap_ctx, NULL, FD_SNAPSHOT_RESTORE_NONE );
    }
    base_slot = fd_snapshot_get_slot( snap_ctx );

    fd_snapshot_load_accounts( snap_ctx );
    fd_snapshot_load_fini( snap_ctx );
  }

  if( strlen( incremental ) > 0 && strcmp( snapshot, "funk" ) != 0 ) {

    /* The slot of the full snapshot should be used as the base slot to verify the incremental snapshot,
       not the slot context's slot - which is the slot of the incremental, not the full snapshot. */
    fd_snapshot_load_all( incremental,
                          ctx->incremental_src_type,
                          NULL,
                          ctx->slot_ctx,
                          &base_slot,
                          NULL,
                          false,
                          false,
                          FD_SNAPSHOT_TYPE_INCREMENTAL,
                          ctx->exec_spads,
                          ctx->exec_spad_cnt,
                          ctx->runtime_spad );
  }

  fd_runtime_update_leaders( ctx->slot_ctx,
                             ctx->slot_ctx->slot_bank.slot,
                             ctx->runtime_spad );
  FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

  fd_exec_para_cb_ctx_t exec_para_ctx = {
    .func       = bpf_tiles_cb,
    .para_arg_1 = ctx,
    .para_arg_2 = stem
  };
  fd_bpf_scan_and_create_bpf_program_cache_entry_para( ctx->slot_ctx,
                                                       ctx->runtime_spad,
                                                       &exec_para_ctx );
  FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx,
                     fd_stem_context_t *    stem ) {
  /* Do not modify order! */

  /* First, load in the sysvars into the sysvar cache. This is required to
     make the StakeHistory sysvar available to the rewards calculation. */

  fd_runtime_sysvar_cache_load( ctx->slot_ctx, ctx->runtime_spad );

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->slot_ctx,
                                              NULL,
                                              ctx->exec_spads,
                                              ctx->exec_spad_cnt,
                                              ctx->runtime_spad );

  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    /* Genesis-specific setup. */
    /* FIXME: This branch does not set up a new block exec ctx
       properly. Needs to do whatever prepare_new_block_execution
       does, but just hacking that in breaks stuff. */
    fd_runtime_update_leaders( ctx->slot_ctx,
                               ctx->slot_ctx->slot_bank.slot,
                               ctx->runtime_spad );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;

    ulong hashcnt_per_slot = ctx->slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * ctx->slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
    while(hashcnt_per_slot--) {
      fd_sha256_hash( ctx->slot_ctx->slot_bank.poh.uc, 32UL, ctx->slot_ctx->slot_bank.poh.uc );
    }

    FD_TEST( fd_runtime_block_execute_prepare( ctx->slot_ctx, ctx->runtime_spad ) == 0 );
    fd_runtime_block_info_t info = { .signature_cnt = 0 };

    fd_exec_para_cb_ctx_t exec_para_ctx_block_finalize = {
      .func       = block_finalize_tiles_cb,
      .para_arg_1 = ctx,
      .para_arg_2 = stem,
    };

    fd_runtime_block_execute_finalize_para( ctx->slot_ctx,
                                            ctx->capture_ctx,
                                            &info,
                                            ctx->exec_cnt,
                                            ctx->runtime_spad,
                                            &exec_para_ctx_block_finalize );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;
    snapshot_slot                      = 1UL;

    fd_exec_para_cb_ctx_t exec_para_ctx_bpf = {
      .func       = bpf_tiles_cb,
      .para_arg_1 = ctx,
      .para_arg_2 = stem
    };

    FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
    fd_bpf_scan_and_create_bpf_program_cache_entry_para( ctx->slot_ctx,
                                                         ctx->runtime_spad,
                                                         &exec_para_ctx_bpf );
    FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

    /* On boot, we want to send all of the relevant epoch-level
       information to each of the exec tiles.  */
  }

  ctx->curr_slot     = snapshot_slot;
  ctx->parent_slot   = ctx->slot_ctx->slot_bank.prev_slot;
  ctx->snapshot_slot = snapshot_slot;
  ctx->flags         = EXEC_FLAG_READY_NEW;

  /* Initialize consensus structures post-snapshot */

  fd_fork_t * snapshot_fork = fd_forks_init( ctx->forks, ctx->slot_ctx );
  FD_TEST( snapshot_fork );
  fd_epoch_init( ctx->epoch, &snapshot_fork->slot_ctx->epoch_ctx->epoch_bank );
  fd_ghost_init( ctx->ghost, snapshot_slot );

  fd_funk_rec_key_t key = { 0 };
  memcpy( key.uc, ctx->vote_acc, sizeof(fd_pubkey_t) );
  key.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_TYPE_ACC;
  fd_tower_from_vote_acc( ctx->tower, ctx->funk, snapshot_fork->slot_ctx->funk_txn, &key );
  FD_LOG_NOTICE(( "vote account: %s", FD_BASE58_ENC_32_ALLOCA( key.uc ) ));
  fd_tower_print( ctx->tower, ctx->root );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->epoch_ctx->bank_hash_cmp;
  bank_hash_cmp->total_stake         = ctx->epoch->total_stake;
  bank_hash_cmp->watermark           = snapshot_slot;

  fd_epoch_fork_elem_t * curr_entry = &ctx->epoch_forks->forks[ 0 ];

  if( strlen( ctx->genesis ) > 0 ) {
    curr_entry->parent_slot = 0UL;
    curr_entry->epoch       = 0UL;
  } else {
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->epoch_ctx );

    ulong curr_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, ctx->curr_slot, NULL );
    ulong last_slot_in_epoch = fd_ulong_sat_sub( fd_epoch_slot0( &epoch_bank->epoch_schedule, curr_epoch), 1UL );

    curr_entry->parent_slot = fd_ulong_min( ctx->parent_slot, last_slot_in_epoch );
    curr_entry->epoch = curr_epoch;
  }

  curr_entry->epoch_ctx = ctx->epoch_ctx;
  ctx->epoch_forks->curr_epoch_idx = 0UL;

  ulong wmark = snapshot_slot;
  if( FD_LIKELY( wmark > fd_fseq_query( ctx->published_wmark ) ) ) {

    /* The watermark has advanced likely because we loaded an
       incremental snapshot that was downloaded just-in-time.  We had
       kicked off repair with an older incremental snapshot, and so now
       we have to prune the relevant data structures, so replay can
       start from the latest frontier.

       No funk_and_txncache_publish( ctx, wmark, &xid ); because there
       are no funk txns to publish, and all rooted slots have already
       been registered in the txncache when we loaded the snapshot. */

    FD_LOG_NOTICE(( "wmk %lu => %lu", fd_fseq_query( ctx->published_wmark ), wmark ));
    if( FD_LIKELY( ctx->blockstore ) ) fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, wmark );
    if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, wmark, ctx->ghost );
    if( FD_LIKELY( ctx->ghost ) ) {
      fd_epoch_forks_publish( ctx->epoch_forks, ctx->ghost, wmark );
      fd_ghost_publish( ctx->ghost, wmark );
    }
    fd_fseq_update( ctx->published_wmark, wmark );
  }

  FD_LOG_NOTICE(( "snapshot slot %lu", snapshot_slot ));
}

void
init_snapshot( fd_replay_tile_ctx_t * ctx,
               fd_stem_context_t *    stem ) {
  /* Init slot_ctx */

  uchar * slot_ctx_mem        = fd_spad_alloc_check( ctx->runtime_spad, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT );
  ctx->slot_ctx               = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, ctx->runtime_spad ) );
  ctx->slot_ctx->funk         = ctx->funk;
  ctx->slot_ctx->blockstore   = ctx->blockstore;
  ctx->slot_ctx->epoch_ctx    = ctx->epoch_ctx;
  ctx->slot_ctx->status_cache = ctx->status_cache;
  fd_runtime_update_slots_per_epoch( ctx->slot_ctx, FD_DEFAULT_SLOTS_PER_EPOCH );

  uchar is_snapshot = strlen( ctx->snapshot ) > 0;
  if( is_snapshot ) {
    read_snapshot( ctx, stem, ctx->snapshot, ctx->incremental, ctx->snapshot_dir );
  }

  if( ctx->plugin_out->mem ) {
    uchar msg[56];
    fd_memset( msg, 0, sizeof(msg) );
    msg[ 0 ] = 6;
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
  }

  fd_runtime_read_genesis( ctx->slot_ctx,
                           ctx->genesis,
                           is_snapshot,
                           ctx->capture_ctx,
                           ctx->runtime_spad );
  /* We call this after fd_runtime_read_genesis, which sets up the
     slot_bank needed in blockstore_init. */
  /* FIXME We should really only call this once. */
  fd_blockstore_init( ctx->slot_ctx->blockstore,
                      ctx->blockstore_fd,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      &ctx->slot_ctx->slot_bank );
  ctx->epoch_ctx->bank_hash_cmp  = ctx->bank_hash_cmp;
  ctx->epoch_ctx->runtime_public = ctx->runtime_public;
  init_after_snapshot( ctx, stem );

  if( ctx->plugin_out->mem && strlen( ctx->genesis ) > 0 ) {
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_GENESIS_HASH_KNOWN, ctx->epoch_ctx->epoch_bank.genesis_hash.uc, sizeof(fd_hash_t) );
  }

  /* Redirect ctx->slot_ctx to point to the memory inside forks. */

  fd_fork_t * fork = fd_forks_query( ctx->forks, ctx->curr_slot );
  ctx->slot_ctx = fork->slot_ctx;

  // Tell the world about the current activate features
  fd_memcpy( &ctx->runtime_public->features, &ctx->slot_ctx->epoch_ctx->features, sizeof(ctx->runtime_public->features) );

  send_exec_epoch_msg( ctx, stem, ctx->slot_ctx );

  /* Publish slot notifs */
  ulong curr_slot = ctx->curr_slot;
  ulong block_entry_height = 0;

  if( is_snapshot ){
    for(;;){
      fd_block_map_query_t query[1] = { 0 };
      int err = fd_block_map_query_try( ctx->blockstore->block_map, &curr_slot, NULL, query, 0 );
      fd_block_info_t * block_info = fd_block_map_query_ele( query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY   ) ) FD_LOG_ERR(( "Failed to query blockstore for slot %lu", curr_slot ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) {
        FD_LOG_WARNING(( "Waiting for block map query for slot %lu", curr_slot ));
        continue;
      };
      block_entry_height = block_info->block_height;
      if( FD_UNLIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) break;
    }
  } else {
    /* Block after genesis has a height of 1.
       TODO: We should be able to query slot 1 block_map entry to get this
       (using the above for loop), but blockstore/fork setup on genesis is
       broken for now. */
    block_entry_height = 1UL;
    init_poh( ctx );
  }

  publish_slot_notifications( ctx, stem, fork, block_entry_height, curr_slot );


  FD_TEST( ctx->slot_ctx );
}

static void
publish_votes_to_plugin( fd_replay_tile_ctx_t * ctx,
                         fd_stem_context_t *    stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->votes_plugin_out->mem, ctx->votes_plugin_out->chunk );

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY ( !fork  ) ) return;
  fd_vote_accounts_t * accts = &fork->slot_ctx->slot_bank.epoch_stakes;
  fd_vote_accounts_pair_t_mapnode_t * root = accts->vote_accounts_root;
  fd_vote_accounts_pair_t_mapnode_t * pool = accts->vote_accounts_pool;

  ulong i = 0;
  FD_SPAD_FRAME_BEGIN( ctx->runtime_spad ) {
  for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( pool, root );
       n && i < FD_CLUSTER_NODE_CNT;
       n = fd_vote_accounts_pair_t_map_successor_const( pool, n ) ) {
    if( n->elem.stake == 0 ) continue;

    int err;
    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, ctx->runtime_spad,
        n->elem.value.data,
        n->elem.value.data_len,
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unexpected failure in decoding vote state" ));
    }

    fd_pubkey_t node_pubkey;
    ulong       commission;
    ulong       epoch_credits;
    fd_vote_epoch_credits_t const * _epoch_credits;
    ulong       root_slot;

    switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        node_pubkey   = vsv->inner.v0_23_5.node_pubkey;
        commission    = vsv->inner.v0_23_5.commission;
        _epoch_credits = deq_fd_vote_epoch_credits_t_cnt( vsv->inner.v0_23_5.epoch_credits ) == 0 ? NULL : deq_fd_vote_epoch_credits_t_peek_tail_const( vsv->inner.v0_23_5.epoch_credits );
        epoch_credits = _epoch_credits==NULL ? 0UL : _epoch_credits->credits - _epoch_credits->prev_credits;
        root_slot     = vsv->inner.v0_23_5.root_slot;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        node_pubkey   = vsv->inner.v1_14_11.node_pubkey;
        commission    = vsv->inner.v1_14_11.commission;
        _epoch_credits = deq_fd_vote_epoch_credits_t_cnt( vsv->inner.v1_14_11.epoch_credits ) == 0 ? NULL : deq_fd_vote_epoch_credits_t_peek_tail_const( vsv->inner.v1_14_11.epoch_credits );
        epoch_credits = _epoch_credits==NULL ? 0UL : _epoch_credits->credits - _epoch_credits->prev_credits;
        root_slot     = vsv->inner.v1_14_11.root_slot;
        break;
      case fd_vote_state_versioned_enum_current:
        node_pubkey   = vsv->inner.current.node_pubkey;
        commission    = vsv->inner.current.commission;
        _epoch_credits = deq_fd_vote_epoch_credits_t_cnt( vsv->inner.current.epoch_credits ) == 0 ? NULL : deq_fd_vote_epoch_credits_t_peek_tail_const( vsv->inner.current.epoch_credits );
        epoch_credits = _epoch_credits==NULL ? 0UL : _epoch_credits->credits - _epoch_credits->prev_credits;
        root_slot     = vsv->inner.v0_23_5.root_slot;
        break;
      default:
        __builtin_unreachable();
    }

    fd_clock_timestamp_vote_t_mapnode_t query;
    memcpy( query.elem.pubkey.uc, n->elem.key.uc, 32UL );
    fd_clock_timestamp_vote_t_mapnode_t * res = fd_clock_timestamp_vote_t_map_find( fork->slot_ctx->slot_bank.timestamp_votes.votes_pool, fork->slot_ctx->slot_bank.timestamp_votes.votes_root, &query );

    fd_vote_update_msg_t * msg = (fd_vote_update_msg_t *)(dst + sizeof(ulong) + i*112U);
    memset( msg, 0, 112U );
    memcpy( msg->vote_pubkey, n->elem.key.uc, sizeof(fd_pubkey_t) );
    memcpy( msg->node_pubkey, node_pubkey.uc, sizeof(fd_pubkey_t) );
    msg->activated_stake = n->elem.stake;
    msg->last_vote       = res == NULL ? 0UL : res->elem.slot;
    msg->root_slot       = root_slot;
    msg->epoch_credits   = epoch_credits;
    msg->commission      = (uchar)commission;
    msg->is_delinquent   = (uchar)fd_int_if(ctx->curr_slot >= 128UL, msg->last_vote <= ctx->curr_slot - 128UL, msg->last_vote == 0);
    ++i;
  }
  } FD_SPAD_FRAME_END;

  *(ulong *)dst = i;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->votes_plugin_out->idx, FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE, ctx->votes_plugin_out->chunk, 0, 0UL, 0UL, tspub );
  ctx->votes_plugin_out->chunk = fd_dcache_compact_next( ctx->votes_plugin_out->chunk, 8UL + 40200UL*(58UL+12UL*34UL), ctx->votes_plugin_out->chunk0, ctx->votes_plugin_out->wmark );
}

static void /* could be moved */
join_txn_ctx( fd_replay_tile_ctx_t * ctx,
              ulong                  exec_tile_idx,
              uint                   txn_ctx_offset ) {

  /* The txn ctx offset is an offset from its respective exec spad.*/
  ulong exec_spad_gaddr = fd_wksp_gaddr( ctx->exec_spads_wksp[ exec_tile_idx ], ctx->exec_spads[ exec_tile_idx ] );
  if( FD_UNLIKELY( !exec_spad_gaddr ) ) {
    FD_LOG_ERR(( "Unable to get gaddr of the exec spad" ));
  }


  ulong   txn_ctx_gaddr = exec_spad_gaddr + (ulong)txn_ctx_offset;
  uchar * txn_ctx_laddr = fd_wksp_laddr( ctx->exec_spads_wksp[ exec_tile_idx ], txn_ctx_gaddr );
  if( FD_UNLIKELY( !txn_ctx_laddr ) ) {
    FD_LOG_ERR(( "Unable to get laddr of the txn ctx" ));
  }

  ctx->exec_txn_ctxs[ exec_tile_idx ] = fd_exec_txn_ctx_join( txn_ctx_laddr,
                                                              ctx->exec_spads[ exec_tile_idx ],
                                                              ctx->exec_spads_wksp[ exec_tile_idx ] );
  if( FD_UNLIKELY( !ctx->exec_txn_ctxs[ exec_tile_idx ] ) ) {
    FD_LOG_ERR(( "Unable to join txn ctx" ));
  }
}

static void
handle_exec_state_updates( fd_replay_tile_ctx_t * ctx ) {

  /* This function is responsible for updating the local view for the
     states of the exec tiles. */

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ulong res = fd_fseq_query( ctx->exec_fseq[ i ] );
    if( FD_UNLIKELY( fd_exec_fseq_is_not_joined( res ) ) ) {
      FD_LOG_WARNING(( "exec tile fseq idx=%lu has not been joined by the corresponding exec tile", i ));
      continue;
    }

    uint state  = fd_exec_fseq_get_state( res );
    switch( state ) {
      case FD_EXEC_STATE_NOT_BOOTED:
        /* Init is not complete in the exec tile for some reason. */
        FD_LOG_WARNING(( "Exec tile idx=%lu is not booted", i ));
        break;
      case FD_EXEC_STATE_BOOTED:
        if( ctx->exec_ready[ i ] == EXEC_BOOT_WAIT ) {
          FD_LOG_INFO(( "Exec tile idx=%lu is booted", i ));
          join_txn_ctx( ctx, i, fd_exec_fseq_get_booted_offset( res ) );
        }
        break;
      case FD_EXEC_STATE_EPOCH_DONE:
        if( ctx->exec_ready[ i ]==EXEC_EPOCH_WAIT ) {
          /* This log may not always show up but that's fine because the
             replay_exec link is reliable and so the epoch message is
             guaranteed to be delivered. */
          FD_LOG_INFO(( "Ack that exec tile idx=%lu has processed epoch message", i ));
          ctx->exec_ready[ i ] = EXEC_EPOCH_DONE;
        }
        break;
      case FD_EXEC_STATE_SLOT_DONE:
        if( ctx->exec_ready[ i ]==EXEC_SLOT_WAIT ) {
          FD_LOG_INFO(( "Ack that exec tile idx=%lu has processed slot message", i ));
          ctx->exec_ready[ i ] = EXEC_TXN_READY;
        }
        break;
      case FD_EXEC_STATE_HASH_DONE:
        break;
      case FD_EXEC_STATE_BPF_SCAN_DONE:
        break;
      default:
        FD_LOG_ERR(( "Unexpected fseq state from exec tile idx=%lu state=%u", i, state ));
        break;
    }
  }
}

static void
handle_writer_state_updates( fd_replay_tile_ctx_t * ctx ) {

  for( ulong i=0UL; i<ctx->writer_cnt; i++ ) {
    ulong res = fd_fseq_query( ctx->writer_fseq[ i ] );
    if( FD_UNLIKELY( fd_writer_fseq_is_not_joined( res ) ) ) {
      FD_LOG_WARNING(( "writer tile fseq idx=%lu has not been joined by the corresponding writer tile", i ));
      continue;
    }

    uint state = fd_writer_fseq_get_state( res );
    switch( state ) {
      case FD_WRITER_STATE_NOT_BOOTED:
        FD_LOG_WARNING(( "writer tile idx=%lu is still booting", i ));
        break;
      case FD_WRITER_STATE_READY:
        /* No-op. */
        break;
      case FD_WRITER_STATE_TXN_DONE: {
        uint  txn_id       = fd_writer_fseq_get_txn_id( res );
        ulong exec_tile_id = fd_writer_fseq_get_exec_tile_id( res );
        if( ctx->exec_ready[ exec_tile_id ]==EXEC_TXN_BUSY && ctx->prev_ids[ exec_tile_id ]!=txn_id ) {
          FD_LOG_DEBUG(( "Ack that exec tile idx=%lu txn id=%u has been finalized by writer tile %lu", exec_tile_id, txn_id, i ));
          ctx->exec_ready[ exec_tile_id ] = EXEC_TXN_READY;
          ctx->prev_ids[ exec_tile_id ]   = txn_id;
          fd_fseq_update( ctx->writer_fseq[ i ], FD_WRITER_STATE_READY );
        }
        break;
      }
      default:
        FD_LOG_CRIT(( "Unexpected fseq state from writer tile idx=%lu state=%u", i, state ));
        break;
    }
  }

}

static void
after_credit( fd_replay_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy FD_PARAM_UNUSED ) {

  /* TODO: Consider moving state management to during_housekeeping */

  /* Check all the writer link fseqs. */
  handle_writer_state_updates( ctx );

  /* Check all the exec link fseqs and handle any updates if needed. */
  handle_exec_state_updates( ctx );

  /* If we are ready to process a new slice, we will poll for it and try
     to setup execution for it. */
  if( ctx->flags & EXEC_FLAG_READY_NEW ) {
    handle_slice( ctx, stem );
  }

  /* If we are currently executing a slice, proceed. */
  if( ctx->flags & EXEC_FLAG_EXECUTING_SLICE ) {
    exec_slice( ctx, stem, ctx->curr_slot );
  }

  ulong curr_slot   = ctx->curr_slot;
  ulong parent_slot = ctx->parent_slot;
  ulong flags       = ctx->flags;

  /* Finished replaying a slot in this after_credit iteration. */
  if( FD_UNLIKELY( flags & EXEC_FLAG_FINISHED_SLOT ) ){
    fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );

    FD_LOG_NOTICE(( "finished block - slot: %lu, parent_slot: %lu, txn_cnt: %lu",
                    curr_slot,
                    ctx->parent_slot,
                    fork->slot_ctx->txn_count ));

    /**************************************************************************************************/
    /* Call fd_runtime_block_execute_finalize_tpool which updates sysvar and cleanup some other stuff */
    /**************************************************************************************************/

    fd_runtime_block_info_t runtime_block_info[1];
    runtime_block_info->signature_cnt = fork->slot_ctx->signature_cnt;

    ctx->block_finalizing = 0;

    fd_exec_para_cb_ctx_t exec_para_ctx_block_finalize = {
      .func       = block_finalize_tiles_cb,
      .para_arg_1 = ctx,
      .para_arg_2 = stem,
    };

    fd_runtime_block_execute_finalize_para( ctx->slot_ctx,
                                            ctx->capture_ctx,
                                            runtime_block_info,
                                            ctx->exec_cnt,
                                            ctx->runtime_spad,
                                            &exec_para_ctx_block_finalize );

    fd_spad_pop( ctx->runtime_spad );
    FD_LOG_NOTICE(( "Spad memory after executing block %lu", ctx->runtime_spad->mem_used ));

    /**********************************************************************/
    /* Push notifications for slot updates and reset block_info flag */
    /**********************************************************************/

    ulong block_entry_height = fd_blockstore_block_height_query( ctx->blockstore, curr_slot );
    publish_slot_notifications( ctx, stem, fork, block_entry_height, curr_slot );

    ctx->blockstore->shmem->lps = curr_slot;

    /**********************************************************************/
    /* Unlock the fork meaning that execution of the fork is now complete */
    /**********************************************************************/

    FD_TEST(fork->slot == curr_slot);
    fork->lock = 0;

    /**********************************************************************/
    /* Consensus: update ghost and forks                                  */
    /**********************************************************************/

    fd_ghost_node_t const * ghost_node = fd_ghost_insert( ctx->ghost, parent_slot, curr_slot );
#if FD_GHOST_USE_HANDHOLDING
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR(( "failed to insert ghost node %lu", curr_slot ));
    }
#endif

    ulong prev_confirmed = ctx->forks->confirmed;
    ulong prev_finalized = ctx->forks->finalized;
    fd_forks_update( ctx->forks, ctx->epoch, ctx->funk, ctx->ghost, curr_slot );

    if (FD_UNLIKELY( prev_confirmed!=ctx->forks->confirmed && ctx->plugin_out->mem ) ) {
      ulong msg[ 1 ] = { ctx->forks->confirmed };
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED, (uchar const *)msg, sizeof(msg) );
    }

    if (FD_UNLIKELY( prev_finalized!=ctx->forks->finalized && ctx->plugin_out->mem ) ) {
      ulong msg[ 1 ] = { ctx->forks->finalized };
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_ROOTED, (uchar const *)msg, sizeof(msg) );
    }

    fd_forks_print( ctx->forks );
    fd_ghost_print( ctx->ghost, ctx->epoch, fd_ghost_root( ctx->ghost ) );
    fd_tower_print( ctx->tower, ctx->root );

    fd_fork_t * child = fd_fork_frontier_ele_query( ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );
    ulong vote_slot   = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->funk, child->slot_ctx->funk_txn, ctx->ghost, ctx->runtime_spad );

    FD_LOG_NOTICE( ( "\n\n[Fork Selection]\n"
                     "# of vote accounts: %lu\n"
                     "best fork:          %lu\n",
                     fd_epoch_voters_key_cnt( fd_epoch_voters( ctx->epoch ) ),
                     fd_ghost_head( ctx->ghost, fd_ghost_root( ctx->ghost ) )->slot ) );

    /**********************************************************************/
    /* Consensus: send out a new vote by calling send_tower_sync          */
    /**********************************************************************/

    if( FD_UNLIKELY( ctx->vote && fd_fseq_query( ctx->poh ) == ULONG_MAX ) ) {
      /* Only proceed with voting if we're caught up. */

      FD_LOG_WARNING(( "still catching up. not voting." ));
    } else {
      if( FD_UNLIKELY( !ctx->is_caught_up ) ) {
        ctx->is_caught_up = 1;
      }

      /* Proceed according to how local and cluster are synchronized. */

      if( FD_LIKELY( vote_slot != FD_SLOT_NULL ) ) {

        /* Invariant check: the vote_slot must be in the frontier */

        FD_TEST( fd_forks_query_const( ctx->forks, vote_slot ) );

        /* Vote locally */

        ulong root = fd_tower_vote( ctx->tower, vote_slot );
        ctx->metrics.last_voted_slot = vote_slot;

        /* Update to a new root, if there is one. */

        if ( FD_LIKELY ( root != FD_SLOT_NULL ) ) ctx->root = root; /* optimize for full tower (replay is keeping up) */
      }

      /* Send our updated tower to the cluster. */

      send_tower_sync( ctx );
    }

    /**********************************************************************/
    /* Prepare bank for the next execution and write to debugging files   */
    /**********************************************************************/

    ulong prev_slot = child->slot_ctx->slot_bank.slot;
    child->slot_ctx->slot_bank.slot                     = curr_slot;
    child->slot_ctx->slot_bank.collected_execution_fees = 0UL;
    child->slot_ctx->slot_bank.collected_priority_fees  = 0UL;
    child->slot_ctx->slot_bank.collected_rent           = 0UL;

    if( FD_UNLIKELY( ctx->slots_replayed_file ) ) {
      FD_LOG_DEBUG(( "writing %lu to slots file", prev_slot ));
      fprintf( ctx->slots_replayed_file, "%lu\n", prev_slot );
      fflush( ctx->slots_replayed_file );
    }

    if (NULL != ctx->capture_ctx) {
      fd_solcap_writer_flush( ctx->capture_ctx->capture );
    }

    /**********************************************************************/
    /* Bank hash comparison, and halt if there's a mismatch after replay  */
    /**********************************************************************/

    fd_hash_t const * bank_hash = &child->slot_ctx->slot_bank.banks_hash;
    fd_bank_hash_cmp_t * bank_hash_cmp = child->slot_ctx->epoch_ctx->bank_hash_cmp;
    fd_bank_hash_cmp_lock( bank_hash_cmp );
    fd_bank_hash_cmp_insert( bank_hash_cmp, curr_slot, bank_hash, 1, 0 );

    /* Try to move the bank hash comparison watermark forward */
    for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < curr_slot; cmp_slot++ ) {
      int rc = fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot );
      switch ( rc ) {
        case -1:

          /* Mismatch */

          //funk_cancel( ctx, cmp_slot );
          //checkpt( ctx );
          (void)checkpt;
          FD_LOG_WARNING(( "Bank hash mismatch on slot: %lu. Halting.", cmp_slot ));

          break;

        case 0:

          /* Not ready */

          break;

        case 1:

          /* Match*/

          bank_hash_cmp->watermark = cmp_slot;
          break;

        default:;
      }
    }

    fd_bank_hash_cmp_unlock( bank_hash_cmp );
    ctx->flags = EXEC_FLAG_READY_NEW;
  } // end of if( FD_UNLIKELY( ( flags & REPLAY_FLAG_FINISHED_BLOCK ) ) )

  if( FD_UNLIKELY( !ctx->snapshot_init_done ) ) {
    if( ctx->plugin_out->mem ) {
      uchar msg[56];
      fd_memset( msg, 0, sizeof(msg) );
      msg[ 0 ] = 0; // ValidatorStartProgress::Initializing
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
    }
    init_snapshot( ctx, stem );
    ctx->snapshot_init_done = 1;
    //*charge_busy = 0;
  }

  long now = fd_log_wallclock();
  if( ctx->votes_plugin_out->mem && FD_UNLIKELY( ( now - ctx->last_plugin_push_time )>PLUGIN_PUBLISH_TIME_NS ) ) {
    ctx->last_plugin_push_time = now;
    publish_votes_to_plugin( ctx, stem );
  }

}

static void
during_housekeeping( void * _ctx ) {

  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  /* Update watermark. The publish watermark is the minimum of the tower
     root and supermajority root. */

  ulong wmark = fd_ulong_min( ctx->root, ctx->forks->finalized );

  if( FD_LIKELY( wmark <= fd_fseq_query( ctx->published_wmark ) ) ) return;
  FD_LOG_NOTICE(( "advancing wmark %lu => %lu", fd_fseq_query( ctx->published_wmark ), wmark ));

  fd_funk_txn_xid_t xid = { .ul = { wmark, wmark } };
  if( FD_LIKELY( ctx->blockstore ) ) fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, wmark );
  if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, wmark, ctx->ghost );
  if( FD_LIKELY( ctx->funk ) ) funk_and_txncache_publish( ctx, wmark, &xid );
  if( FD_LIKELY( ctx->ghost ) ) {
    fd_epoch_forks_publish( ctx->epoch_forks, ctx->ghost, wmark );
    fd_ghost_publish( ctx->ghost, wmark );
  }

  fd_fseq_update( ctx->published_wmark, wmark );


  // fd_mcache_seq_update( ctx->store_out_sync, ctx->store_out_seq );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );
  memset( ctx, 0, sizeof(fd_replay_tile_ctx_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->funk_seed, sizeof(ulong), 0 ) );
  FD_TEST( sizeof(ulong) == getrandom( &ctx->status_cache_seed, sizeof(ulong), 0 ) );

  ctx->blockstore_fd = open( tile->replay.blockstore_file, O_RDWR | O_CREAT, 0666 );
  if( FD_UNLIKELY( ctx->blockstore_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create blockstore archival file %s %d %d %s", tile->replay.blockstore_file, ctx->blockstore_fd, errno, strerror(errno) ));
  }

  /**********************************************************************/
  /* runtime public                                                      */
  /**********************************************************************/

  ulong replay_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "runtime_pub" );
  if( FD_UNLIKELY( replay_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "no runtime_public" ));
  }

  ctx->runtime_public_wksp = topo->workspaces[ topo->objs[ replay_obj_id ].wksp_id ].wksp;
  if( ctx->runtime_public_wksp==NULL ) {
    FD_LOG_ERR(( "no runtime_public workspace" ));
  }

  ctx->runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, replay_obj_id ) );
  if( FD_UNLIKELY( !ctx->runtime_public ) ) {
    FD_LOG_ERR(( "no runtime_public" ));
  }


  /* Open Funk */
  fd_funk_txn_start_write( NULL );
  fd_funk_t * funk;
  const char * snapshot = tile->replay.snapshot;
  if( strcmp( snapshot, "funk" ) == 0 ) {
    /* Funk database already exists. The parameters are actually mostly ignored. */
    funk = fd_funk_open_file(
        ctx->funk,
        tile->replay.funk_file, 1, ctx->funk_seed, tile->replay.funk_txn_max,
        tile->replay.funk_rec_max, tile->replay.funk_sz_gb * (1UL<<30),
        FD_FUNK_READ_WRITE, NULL );
  } else if( strncmp( snapshot, "wksp:", 5 ) == 0) {
    /* Recover funk database from a checkpoint. */
    funk = fd_funk_recover_checkpoint( ctx->funk, tile->replay.funk_file, 1, snapshot+5, NULL );
  } else {
    FD_LOG_NOTICE(( "Trying to create new funk at file=%s", tile->replay.funk_file ));
    /* Create new funk database */
    funk = fd_funk_open_file(
        ctx->funk,
        tile->replay.funk_file, 1, ctx->funk_seed, tile->replay.funk_txn_max,
        tile->replay.funk_rec_max, tile->replay.funk_sz_gb * (1UL<<30),
        FD_FUNK_OVERWRITE, NULL );
    FD_LOG_NOTICE(( "Opened funk file at %s", tile->replay.funk_file ));
  }
  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_ERR(( "Failed to join funk database" ));
  }
  fd_funk_txn_end_write( NULL );
  ctx->funk_wksp = fd_funk_wksp( funk );
  if( FD_UNLIKELY( ctx->funk_wksp == NULL ) ) {
    FD_LOG_ERR(( "no funk wksp" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  FD_LOG_NOTICE(("Starting unprivileged init"));
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt < 3 ||
                   strcmp( topo->links[ tile->in_link_id[ PACK_IN_IDX ] ].name, "pack_replay")   ||
                   strcmp( topo->links[ tile->in_link_id[ BATCH_IN_IDX  ] ].name, "batch_replay" ) ||
                   strcmp( topo->links[ tile->in_link_id[ REPAIR_IN_IDX  ] ].name, "repair_repla" ) ) ) {
    FD_LOG_ERR(( "replay tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * epoch_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  void * tower_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    ctx->bmtree[i]           = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  void * mbatch_mem          = FD_SCRATCH_ALLOC_APPEND( l, 128UL, FD_SLICE_MAX );
  ulong  scratch_alloc_mem   = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );

  if( FD_UNLIKELY( scratch_alloc_mem != ( (ulong)scratch + scratch_footprint( tile ) ) ) ) {
    FD_LOG_ERR( ( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
          scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
          scratch_alloc_mem,
          (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /**********************************************************************/
  /* wksp                                                               */
  /**********************************************************************/

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;
  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blockstore wksp" ));
  }

  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  fd_buf_shred_pool_reset( ctx->blockstore->shred_pool, 0 );
  FD_TEST( ctx->blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );

  ulong status_cache_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "txncache" );
  FD_TEST( status_cache_obj_id != ULONG_MAX );
  ctx->status_cache_wksp = topo->workspaces[topo->objs[status_cache_obj_id].wksp_id].wksp;
  if( ctx->status_cache_wksp == NULL ) {
    FD_LOG_ERR(( "no status cache wksp" ));
  }

  /**********************************************************************/
  /* snapshot                                                           */
  /**********************************************************************/

  ctx->snapshot_interval    = tile->replay.full_interval ? tile->replay.full_interval : ULONG_MAX;
  ctx->incremental_interval = tile->replay.incremental_interval ? tile->replay.incremental_interval : ULONG_MAX;
  ctx->last_full_snap       = 0UL;

  FD_LOG_NOTICE(( "Snapshot intervals full=%lu incremental=%lu", ctx->snapshot_interval, ctx->incremental_interval ));

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  /* TODO: This below code needs to be shared as a topology object. This
     will involve adding support to create a funk-based file here. */

  ctx->is_caught_up = 0;

  /**********************************************************************/
  /* root_slot fseq                                                     */
  /**********************************************************************/

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->published_wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->published_wmark ) );

  /**********************************************************************/
  /* constipated fseq                                                   */
  /**********************************************************************/

  /* When the replay tile boots, funk should not be constipated */

  ulong constipated_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "constipate" );
  FD_TEST( constipated_obj_id!=ULONG_MAX );
  ctx->is_constipated = fd_fseq_join( fd_topo_obj_laddr( topo, constipated_obj_id ) );
  if( FD_UNLIKELY( !ctx->is_constipated ) ) FD_LOG_ERR(( "replay tile has no constipated fseq" ));
  fd_fseq_update( ctx->is_constipated, 0UL );
  FD_TEST( 0UL==fd_fseq_query( ctx->is_constipated ) );

  /**********************************************************************/
  /* poh_slot fseq                                                     */
  /**********************************************************************/

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  /**********************************************************************/
  /* turbine_slot fseq                                                  */
  /**********************************************************************/

  ulong current_turb_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turb_slot" );
  FD_TEST( current_turb_slot_obj_id!=ULONG_MAX );
  ctx->curr_turbine_slot = fd_fseq_join( fd_topo_obj_laddr( topo, current_turb_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->curr_turbine_slot ) ) FD_LOG_ERR(( "replay tile has no turb_slot fseq" ));

  /**********************************************************************/
  /* TOML paths                                                         */
  /**********************************************************************/

  ctx->blockstore_checkpt  = tile->replay.blockstore_checkpt;
  ctx->tx_metadata_storage = tile->replay.tx_metadata_storage;
  ctx->funk_checkpt        = tile->replay.funk_checkpt;
  ctx->genesis             = tile->replay.genesis;
  ctx->incremental         = tile->replay.incremental;
  ctx->snapshot            = tile->replay.snapshot;
  ctx->snapshot_dir        = tile->replay.snapshot_dir;

  ctx->incremental_src_type = tile->replay.incremental_src_type;
  ctx->snapshot_src_type    = tile->replay.snapshot_src_type;

  /**********************************************************************/
  /* status cache                                                       */
  /**********************************************************************/

  char const * status_cache_path = tile->replay.status_cache;
  if ( strlen( status_cache_path ) > 0 ) {
    FD_LOG_NOTICE(("starting status cache restore..."));
    int err = fd_wksp_restore( ctx->status_cache_wksp, status_cache_path, (uint)ctx->status_cache_seed );
    FD_LOG_NOTICE(("finished status cache restore..."));
    if (err) {
      FD_LOG_ERR(( "failed to restore %s: error %d", status_cache_path, err ));
    }
    fd_wksp_tag_query_info_t info;
    ulong tag = FD_TXNCACHE_MAGIC;
    if( fd_wksp_tag_query( ctx->status_cache_wksp, &tag, 1, &info, 1 ) > 0 ) {
      void * status_cache_mem = fd_wksp_laddr_fast( ctx->status_cache_wksp, info.gaddr_lo );
      /* Set up status cache. */
      ctx->status_cache = fd_txncache_join( status_cache_mem );
      if( ctx->status_cache == NULL ) {
        FD_LOG_ERR(( "failed to join status cache in %s", status_cache_path ));
      }
    } else {
      FD_LOG_ERR(( "failed to tag query status cache in %s", status_cache_path ));
    }
  } else {
    void * status_cache_mem = fd_topo_obj_laddr( topo, status_cache_obj_id );
    if (status_cache_mem == NULL) {
      FD_LOG_ERR(( "failed to allocate status cache" ));
    }
    ctx->status_cache = fd_txncache_join( status_cache_mem );
    if (ctx->status_cache == NULL) {
      FD_LOG_ERR(( "failed to join + new status cache" ));
    }
  }

  /**********************************************************************/
  /* spad                                                               */
  /**********************************************************************/

  /* Join each of the exec spads. */
  ctx->exec_cnt = tile->replay.exec_tile_count;
  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ulong       exec_spad_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", i );
    fd_spad_t * spad         = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_id ) );
    ctx->exec_spads[ ctx->exec_spad_cnt ] = spad;
    if( FD_UNLIKELY( !ctx->exec_spads[ ctx->exec_spad_cnt ] ) ) {
      FD_LOG_ERR(( "failed to join exec spad %lu", i ));
    }
    ctx->exec_spads_wksp[ ctx->exec_spad_cnt ] = fd_wksp_containing( spad );
    if( FD_UNLIKELY( !ctx->exec_spads_wksp[ ctx->exec_spad_cnt ] ) ) {
      FD_LOG_ERR(( "failed to join exec spad wksp %lu", i ));
    }

    ctx->exec_spad_cnt++;
  }

  /* Now join the spad that was setup in the runtime public topo obj. */

  ctx->runtime_spad = fd_runtime_public_spad( ctx->runtime_public );
  if( FD_UNLIKELY( !ctx->runtime_spad ) ) {
    FD_LOG_ERR(( "Unable to join the runtime_spad" ));
  }
  fd_spad_push( ctx->runtime_spad );

  /**********************************************************************/
  /* epoch forks                                                        */
  /**********************************************************************/

  void * epoch_ctx_mem = fd_spad_alloc( ctx->runtime_spad,
                                        fd_exec_epoch_ctx_align(),
                                        MAX_EPOCH_FORKS * fd_exec_epoch_ctx_footprint( tile->replay.max_vote_accounts ) );


  fd_epoch_forks_new( ctx->epoch_forks, epoch_ctx_mem );

  /**********************************************************************/
  /* joins                                                              */
  /**********************************************************************/

  uchar * bank_hash_cmp_shmem = fd_spad_alloc_check( ctx->runtime_spad, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint() );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_shmem ) );
  ctx->epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, tile->replay.max_vote_accounts ) );

  if( FD_UNLIKELY( sscanf( tile->replay.cluster_version, "%u.%u.%u", &ctx->epoch_ctx->epoch_bank.cluster_version[0], &ctx->epoch_ctx->epoch_bank.cluster_version[1], &ctx->epoch_ctx->epoch_bank.cluster_version[2] )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version, configured as \"%s\"", tile->replay.cluster_version ));
  }
  fd_features_enable_cleaned_up( &ctx->epoch_ctx->features, ctx->epoch_ctx->epoch_bank.cluster_version );

  char const * one_off_features[16];
  for (ulong i = 0; i < tile->replay.enable_features_cnt; i++) {
    one_off_features[i] = tile->replay.enable_features[i];
  }
  fd_features_enable_one_offs(&ctx->epoch_ctx->features, one_off_features, (uint)tile->replay.enable_features_cnt, 0UL);

  ctx->epoch = fd_epoch_join( fd_epoch_new( epoch_mem, FD_VOTER_MAX ) );
  ctx->forks = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 42UL, FD_BLOCK_MAX ) );
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem ) );

  /**********************************************************************/
  /* voter                                                              */
  /**********************************************************************/

  memcpy( ctx->validator_identity, fd_keyload_load( tile->replay.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  *ctx->vote_authority = *ctx->validator_identity; /* FIXME */
  memcpy( ctx->vote_acc, fd_keyload_load( tile->replay.vote_account_path, 1 ), sizeof(fd_pubkey_t) );

  ctx->vote                           = tile->replay.vote;
  ctx->validator_identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, 1 ) );
  ctx->vote_acct_addr[ 0 ]            = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.vote_account_path, 1 ) );

  /**********************************************************************/
  /* entry batch                                                        */
  /**********************************************************************/

  fd_slice_exec_join( &ctx->slice_exec_ctx );
  ctx->slice_exec_ctx.mbatch = mbatch_mem;

  /**********************************************************************/
  /* capture                                                            */
  /**********************************************************************/

  if( strlen(tile->replay.capture) > 0 ) {
    ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
    ctx->capture_ctx->checkpt_freq = ULONG_MAX;
    ctx->capture_file = fopen( tile->replay.capture, "w+" );
    if( FD_UNLIKELY( !ctx->capture_file ) ) {
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", tile->replay.capture, errno, strerror( errno ) ));
    }
    ctx->capture_ctx->capture_txns = 0;
    fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->capture_file );
  }

  /**********************************************************************/
  /* bank                                                               */
  /**********************************************************************/

  ctx->bank_cnt         = tile->replay.bank_tile_count;
  for( ulong i=0UL; i<tile->replay.bank_tile_count; i++ ) {
    ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", i );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ctx->bank_busy[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    if( FD_UNLIKELY( !ctx->bank_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));

    fd_topo_link_t  * poh_out_link = &topo->links[ tile->out_link_id[ POH_OUT_IDX+i ] ];
    fd_replay_out_link_t * poh_out = &ctx->bank_out[ i ];
    poh_out->mcache                = poh_out_link->mcache;
    poh_out->sync                  = fd_mcache_seq_laddr( poh_out->mcache );
    poh_out->depth                 = fd_mcache_depth( poh_out->mcache );
    poh_out->seq                   = fd_mcache_seq_query( poh_out->sync );
    poh_out->mem                   = topo->workspaces[ topo->objs[ poh_out_link->dcache_obj_id ].wksp_id ].wksp;
    poh_out->chunk0                = fd_dcache_compact_chunk0( poh_out->mem, poh_out_link->dcache );
    poh_out->wmark                 = fd_dcache_compact_wmark( poh_out->mem, poh_out_link->dcache, poh_out_link->mtu );
    poh_out->chunk                 = poh_out->chunk0;
  }

  ctx->poh_init_done      = 0U;
  ctx->snapshot_init_done = 0;

  /**********************************************************************/
  /* exec                                                               */
  /**********************************************************************/
  ctx->exec_cnt = tile->replay.exec_tile_count;
  if( FD_UNLIKELY( ctx->exec_cnt>FD_PACK_MAX_BANK_TILES ) ) {
    FD_LOG_ERR(( "replay tile has too many exec tiles %lu", ctx->exec_cnt ));
  }
  if( FD_UNLIKELY( ctx->exec_cnt>UCHAR_MAX ) ) {
    /* Exec tile id needs to fit in a uchar for the writer tile txn done
       message. */
    FD_LOG_CRIT(( "too many exec tiles %lu", ctx->exec_cnt ));
  }

  for( ulong i = 0UL; i < ctx->exec_cnt; i++ ) {
    /* Mark all initial state as not being ready. */
    ctx->exec_ready[ i ]    = EXEC_BOOT_WAIT;
    ctx->prev_ids[ i ]      = FD_EXEC_ID_SENTINEL;
    ctx->exec_txn_ctxs[ i ] = NULL;

    ulong exec_fseq_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_fseq.%lu", i );
    if( FD_UNLIKELY( exec_fseq_id==ULONG_MAX ) ) {
      FD_LOG_ERR(( "exec tile %lu has no fseq", i ));
    }
    ctx->exec_fseq[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, exec_fseq_id ) );
    if( FD_UNLIKELY( !ctx->exec_fseq[ i ] ) ) {
      FD_LOG_ERR(( "exec tile %lu has no fseq", i ));
    }

    /* Setup out links. */
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "replay_exec", i );
    fd_topo_link_t * exec_out_link = &topo->links[ tile->out_link_id[ idx ] ];

    if( strcmp( exec_out_link->name, "replay_exec" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", idx ));
    }

    fd_replay_out_link_t * exec_out = &ctx->exec_out[ i ];
    exec_out->idx                   = idx;
    exec_out->mem                   = topo->workspaces[ topo->objs[ exec_out_link->dcache_obj_id ].wksp_id ].wksp;
    exec_out->chunk0                = fd_dcache_compact_chunk0( exec_out->mem, exec_out_link->dcache );
    exec_out->wmark                 = fd_dcache_compact_wmark( exec_out->mem, exec_out_link->dcache, exec_out_link->mtu );
    exec_out->chunk                 = exec_out->chunk0;
  }

  /**********************************************************************/
  /* writer                                                             */
  /**********************************************************************/
  ctx->writer_cnt = tile->replay.writer_tile_cuont;
  if( FD_UNLIKELY( ctx->writer_cnt>FD_PACK_MAX_BANK_TILES ) ) {
    FD_LOG_CRIT(( "replay tile has too many writer tiles %lu", ctx->writer_cnt ));
  }

  for( ulong i = 0UL; i < ctx->writer_cnt; i++ ) {

    ulong writer_fseq_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "writer_fseq.%lu", i );
    if( FD_UNLIKELY( writer_fseq_id==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "writer tile %lu has no fseq", i ));
    }
    ctx->writer_fseq[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, writer_fseq_id ) );
    if( FD_UNLIKELY( !ctx->writer_fseq[ i ] ) ) {
      FD_LOG_CRIT(( "writer tile %lu has no fseq", i ));
    }

    /* Setup out links. */
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "replay_wtr", i );
    fd_topo_link_t * writer_out_link = &topo->links[ tile->out_link_id[ idx ] ];

    fd_replay_out_link_t * out = &ctx->writer_out[ i ];
    out->idx                   = idx;
    out->mem                   = topo->workspaces[ topo->objs[ writer_out_link->dcache_obj_id ].wksp_id ].wksp;
    out->chunk0                = fd_dcache_compact_chunk0( out->mem, writer_out_link->dcache );
    out->wmark                 = fd_dcache_compact_wmark( out->mem, writer_out_link->dcache, writer_out_link->mtu );
    out->chunk                 = out->chunk0;
  }

  /**********************************************************************/
  /* tower checkpointing for wen-restart                                */
  /**********************************************************************/
  ctx->tower_checkpt_fileno = -1;
  if( FD_LIKELY( strlen( tile->replay.tower_checkpt )>0 ) ) {
    ctx->tower_checkpt_fileno = open( tile->replay.tower_checkpt,
                                      O_RDWR | O_CREAT,
                                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( ctx->tower_checkpt_fileno<0 ) FD_LOG_ERR(( "Failed at opening the tower checkpoint file" ));
  }

  /**********************************************************************/
  /* links                                                              */
  /**********************************************************************/

  /* Setup store tile input */
  fd_topo_link_t * repair_in_link = &topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ];
  ctx->repair_in_mem              = topo->workspaces[ topo->objs[ repair_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_in_chunk0           = fd_dcache_compact_chunk0( ctx->repair_in_mem, repair_in_link->dcache );
  ctx->repair_in_wmark            = fd_dcache_compact_wmark( ctx->repair_in_mem, repair_in_link->dcache, repair_in_link->mtu );

  /* Setup pack tile input */
  fd_topo_link_t * pack_in_link = &topo->links[ tile->in_link_id[ PACK_IN_IDX ] ];
  ctx->pack_in_mem              = topo->workspaces[ topo->objs[ pack_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0           = fd_dcache_compact_chunk0( ctx->pack_in_mem, pack_in_link->dcache );
  ctx->pack_in_wmark            = fd_dcache_compact_wmark( ctx->pack_in_mem, pack_in_link->dcache, pack_in_link->mtu );

  /* Setup batch tile input for epoch account hash */
  fd_topo_link_t * batch_in_link = &topo->links[ tile->in_link_id[ BATCH_IN_IDX ] ];
  ctx->batch_in_mem              = topo->workspaces[ topo->objs[ batch_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->batch_in_chunk0           = fd_dcache_compact_chunk0( ctx->batch_in_mem, batch_in_link->dcache );
  ctx->batch_in_wmark            = fd_dcache_compact_wmark( ctx->batch_in_mem, batch_in_link->dcache, batch_in_link->mtu );

  ulong replay_notif_idx = fd_topo_find_tile_out_link( topo, tile, "replay_notif", 0 );
  if( FD_UNLIKELY( replay_notif_idx!=ULONG_MAX ) ) {
    fd_topo_link_t * notif_out = &topo->links[ tile->out_link_id[ replay_notif_idx ] ];
    FD_TEST( notif_out );
    ctx->notif_out->idx        = replay_notif_idx;
    ctx->notif_out->mcache     = notif_out->mcache;
    ctx->notif_out->sync       = fd_mcache_seq_laddr( ctx->notif_out->mcache );
    ctx->notif_out->depth      = fd_mcache_depth( ctx->notif_out->mcache );
    ctx->notif_out->seq        = fd_mcache_seq_query( ctx->notif_out->sync );
    ctx->notif_out->mem        = topo->workspaces[ topo->objs[ notif_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->notif_out->chunk0     = fd_dcache_compact_chunk0( ctx->notif_out->mem, notif_out->dcache );
    ctx->notif_out->wmark      = fd_dcache_compact_wmark ( ctx->notif_out->mem, notif_out->dcache, notif_out->mtu );
    ctx->notif_out->chunk      = ctx->notif_out->chunk0;
  } else {
    ctx->notif_out->mcache = NULL;
  }

  fd_topo_link_t * sender_out = &topo->links[ tile->out_link_id[ SENDER_OUT_IDX ] ];
  ctx->sender_out->idx        = SENDER_OUT_IDX;
  ctx->sender_out->mcache     = sender_out->mcache;
  ctx->sender_out->mem        = topo->workspaces[ topo->objs[ sender_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->sender_out->sync       = fd_mcache_seq_laddr     ( ctx->sender_out->mcache );
  ctx->sender_out->depth      = fd_mcache_depth         ( ctx->sender_out->mcache );
  ctx->sender_out->seq        = fd_mcache_seq_query     ( ctx->sender_out->sync );
  ctx->sender_out->chunk0     = fd_dcache_compact_chunk0( ctx->sender_out->mem, sender_out->dcache );
  ctx->sender_out->wmark      = fd_dcache_compact_wmark ( ctx->sender_out->mem, sender_out->dcache, sender_out->mtu );
  ctx->sender_out->chunk      = ctx->sender_out->chunk0;

  /* Set up stake weights tile output */
  fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id[ STAKE_OUT_IDX] ];
  ctx->stake_weights_out->idx        = STAKE_OUT_IDX;
  ctx->stake_weights_out->mcache     = stake_weights_out->mcache;
  ctx->stake_weights_out->mem        = topo->workspaces[ topo->objs[ stake_weights_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_weights_out->sync       = fd_mcache_seq_laddr     ( ctx->stake_weights_out->mcache );
  ctx->stake_weights_out->depth      = fd_mcache_depth         ( ctx->stake_weights_out->mcache );
  ctx->stake_weights_out->seq        = fd_mcache_seq_query     ( ctx->stake_weights_out->sync );
  ctx->stake_weights_out->chunk0     = fd_dcache_compact_chunk0( ctx->stake_weights_out->mem, stake_weights_out->dcache );
  ctx->stake_weights_out->wmark      = fd_dcache_compact_wmark ( ctx->stake_weights_out->mem, stake_weights_out->dcache, stake_weights_out->mtu );
  ctx->stake_weights_out->chunk      = ctx->stake_weights_out->chunk0;

  if( FD_LIKELY( tile->replay.plugins_enabled ) ) {
    ctx->plugin_out->idx = fd_topo_find_tile_out_link( topo, tile, "replay_plugi", 0 );
    fd_topo_link_t const * replay_plugin_out = &topo->links[ tile->out_link_id[ ctx->plugin_out->idx] ];
    if( strcmp( replay_plugin_out->name, "replay_plugi" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", ctx->plugin_out->idx));
    }
    ctx->plugin_out->mem    = topo->workspaces[ topo->objs[ replay_plugin_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->plugin_out->chunk0 = fd_dcache_compact_chunk0( ctx->plugin_out->mem, replay_plugin_out->dcache );
    ctx->plugin_out->wmark  = fd_dcache_compact_wmark ( ctx->plugin_out->mem, replay_plugin_out->dcache, replay_plugin_out->mtu );
    ctx->plugin_out->chunk  = ctx->plugin_out->chunk0;

    ctx->votes_plugin_out->idx = fd_topo_find_tile_out_link( topo, tile, "votes_plugin", 0 );
    fd_topo_link_t const * votes_plugin_out = &topo->links[ tile->out_link_id[ ctx->votes_plugin_out->idx] ];
    if( strcmp( votes_plugin_out->name, "votes_plugin" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", ctx->votes_plugin_out->idx));
    }
    ctx->votes_plugin_out->mem    = topo->workspaces[ topo->objs[ votes_plugin_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->votes_plugin_out->chunk0 = fd_dcache_compact_chunk0( ctx->votes_plugin_out->mem, votes_plugin_out->dcache );
    ctx->votes_plugin_out->wmark  = fd_dcache_compact_wmark ( ctx->votes_plugin_out->mem, votes_plugin_out->dcache, votes_plugin_out->mtu );
    ctx->votes_plugin_out->chunk  = ctx->votes_plugin_out->chunk0;
  }

  if( strnlen( tile->replay.slots_replayed, sizeof(tile->replay.slots_replayed) )>0UL ) {
    ctx->slots_replayed_file = fopen( tile->replay.slots_replayed, "w" );
    FD_TEST( ctx->slots_replayed_file );
  }

  FD_TEST( ctx->runtime_public!=NULL );

  uchar * deque_mem     = fd_spad_alloc_check( ctx->runtime_spad, fd_exec_slice_align(), fd_exec_slice_footprint() );
  ctx->exec_slice_deque = fd_exec_slice_join( fd_exec_slice_new( deque_mem ) );
  if( FD_UNLIKELY( !ctx->exec_slice_deque ) ) {
    FD_LOG_ERR(( "failed to join and create exec slice deque" ));
  }

  FD_LOG_NOTICE(("Finished unprivileged init"));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_replay_tile_ctx_t) );

  populate_sock_filter_policy_fd_replay_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->blockstore_fd );
  return sock_filter_policy_fd_replay_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_replay_tile_ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->blockstore_fd;
  return out_cnt;
}

static inline void
metrics_write( fd_replay_tile_ctx_t * ctx ) {
  FD_MGAUGE_SET( REPLAY, LAST_VOTED_SLOT, ctx->metrics.last_voted_slot );
  FD_MGAUGE_SET( REPLAY, SLOT, ctx->metrics.slot );
}

/* TODO: This needs to get sized out correctly. */
#define STEM_BURST (64UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_replay_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_replay_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_replay = {
    .name                     = "replay",
    .loose_footprint          = loose_footprint,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
