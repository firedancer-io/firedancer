#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "fd_replay_notif.h"

#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_runtime_init.h"
#include "../../flamenco/snapshot/fd_snapshot.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../choreo/fd_choreo.h"
#include "../../disco/plugin/fd_plugin.h"
#include "fd_exec.h"
#include "../../discof/restore/utils/fd_snapshot_messages.h"

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
#define DEQUE_MAX  USHORT_MAX
#include "../../util/tmpl/fd_deque.c"

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_BLK_MAX * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )

#define PLUGIN_PUBLISH_TIME_NS ((long)60e9)

#define REPAIR_IN_IDX   (0UL)
#define PACK_IN_IDX     (1UL)
#define SNAP_IN_IDX     (3UL)

#define EXEC_TXN_BUSY   (0xA)
#define EXEC_TXN_READY  (0xB)

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

  /* Tower tile input */
  ulong tower_in_idx;

  // Notification output defs
  fd_replay_out_link_t notif_out[1];

  // Stake weights output link defs
  fd_replay_out_link_t stake_out[1];

  // Shredcap output link defs
  fd_replay_out_link_t shredcap_out[1];

  ulong       tower_out_idx;
  fd_wksp_t * tower_out_mem;
  ulong       tower_out_chunk0;
  ulong       tower_out_wmark;
  ulong       tower_out_chunk;

  // Inputs to plugin/gui
  fd_replay_out_link_t plugin_out[1];
  fd_replay_out_link_t votes_plugin_out[1];
  long                 last_plugin_push_time;

  char const * blockstore_checkpt;
  int          tx_metadata_storage;
  char const * funk_checkpt;
  char const * genesis;

  /* Do not modify order! This is join-order in unprivileged_init. */

  fd_funk_t             funk[1];
  fd_forks_t          * forks;

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

  /* Metadata updated during execution */

  ulong   snapshot_slot;
  ulong * turbine_slot0;
  ulong * turbine_slot;
  ulong   root; /* the root slot is the most recent slot to have reached
                   max lockout in the tower  */
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

  fd_txncache_t * status_cache;
  void * bmtree[ FD_PACK_MAX_BANK_TILES ];

  /* The spad allocators used by the executor tiles are NOT the same as the
     spad used for general, longer-lasting spad allocations. The lifetime of
     the exec spad is just through an execution. The runtime spad is scoped
     to the runtime. The top-most frame will persist for the entire duration
     of the process. There will also be a potential second frame that persists
     across multiple slots that is created for rewards distrobution. Every other
     spad frame should NOT exist beyond the scope of a block. */

  fd_spad_t *         exec_spads[ FD_PACK_MAX_BANK_TILES ];
  fd_wksp_t *         exec_spads_wksp[ FD_PACK_MAX_BANK_TILES ];
  ulong               exec_spad_cnt;

  fd_spad_t *         runtime_spad;

  fd_funk_txn_t * false_root;

  int read_only; /* The read-only slot is the slot the validator needs
                    to replay through before it can proceed with any
                    write operations such as voting or building blocks.

                    This restriction is for safety reasons: the
                    validator could otherwise equivocate a previous vote
                    or block. */

  int blocked_on_mblock; /* Flag used for synchronizing on mblock boundaries. */

  /* Metrics */
  fd_replay_tile_metrics_t metrics;

  ulong * exec_slice_deque; /* Deque to buffer exec slices - lives in spad */

  ulong enable_bank_hash_cmp;

  fd_banks_t * banks;
  int is_booted;

  /* A hack to get the chunk in after_frag.  Revist as needed. */
  ulong         _snap_out_chunk;
  uchar const * manifest_dcache;          /* Dcache to receive decoded solana manifest */
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
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
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
    /* If the internal slice buffer is full, there is nowhere for the
       fragment to go and we cannot pull it off the incoming queue yet.
       This will eventually cause backpressure to the repair system. */
    if( FD_UNLIKELY( fd_exec_slice_full( ctx->exec_slice_deque ) ) ) return -1;

    FD_LOG_DEBUG(( "rx slice from repair tile %lu %u", fd_disco_repair_replay_sig_slot( sig ), fd_disco_repair_replay_sig_data_cnt( sig ) ));
    fd_exec_slice_push_tail( ctx->exec_slice_deque, sig );
    return 1;
  }
  return 0;
}

/* Large number of helpers for after_credit begin here  */

static void
publish_stake_weights( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t *    stem,
                       fd_exec_slot_ctx_t *   slot_ctx ) {
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

  fd_vote_accounts_global_t const * epoch_stakes = fd_bank_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( epoch_stakes );

  if( epoch_stakes_root!=NULL ) {
    ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
    ulong epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, fd_bank_slot_get( slot_ctx->bank ) );
    ulong stake_weights_sz = generate_stake_weight_msg( slot_ctx, ctx->runtime_spad, epoch - 1, stake_weights_msg );
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );
    FD_LOG_NOTICE(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
  }

  fd_bank_epoch_stakes_end_locking_query( slot_ctx->bank );

  fd_vote_accounts_global_t const * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( next_epoch_stakes );

  if( next_epoch_stakes_root!=NULL ) {
    ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
    ulong   epoch             = fd_slot_to_leader_schedule_epoch( epoch_schedule, fd_bank_slot_get( slot_ctx->bank ) ); /* epoch */
    ulong stake_weights_sz = generate_stake_weight_msg( slot_ctx, ctx->runtime_spad, epoch, stake_weights_msg );
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );
    FD_LOG_NOTICE(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
  }
  fd_bank_next_epoch_stakes_end_locking_query( slot_ctx->bank );
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
    generate_hash_bank_msg( task_infos_gaddr, lt_hash_gaddr, start_idx, end_idx, fd_bank_slot_get( ctx->slot_ctx->bank ), hash_msg );

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
        uint  slot  = fd_exec_fseq_get_slot( res );
        /* We need to compare the state and a unique identifier (slot)
           in the case where the last thing the exec tile did is to hash
           accounts. */
        if( state==FD_EXEC_STATE_HASH_DONE && slot==fd_bank_slot_get( ctx->slot_ctx->bank ) ) {
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

    FD_LOG_INFO(( "Registering slot %lu", slot ));
    fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, slot );

    txn = fd_funk_txn_parent( txn, txn_pool );
  }

  fd_funk_txn_end_read( ctx->funk );
}

static void
funk_publish( fd_replay_tile_ctx_t * ctx,
              fd_funk_txn_t *        to_root_txn,
              ulong                  wmk ) {

  fd_funk_txn_start_write( ctx->funk );
  FD_LOG_DEBUG(( "Publishing slot=%lu xid=%lu", wmk, to_root_txn->xid.ul[0] ));

  /* This is the standard case. Publish all transactions up to and
      including the watermark. This will publish any in-prep ancestors
      of root_txn as well. */
  if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, to_root_txn, 1 ) ) ) {
    FD_LOG_ERR(( "failed to funk publish slot %lu", wmk ));
  }
  fd_funk_txn_end_write( ctx->funk );

  if( FD_LIKELY( FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, epoch_accounts_hash ) &&
                 !FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, accounts_lt_hash ) ) ) {

    if( wmk>=fd_bank_eah_start_slot_get( ctx->slot_ctx->bank ) ) {
      fd_exec_para_cb_ctx_t exec_para_ctx = {
        .func       = fd_accounts_hash_counter_and_gather_tpool_cb,
        .para_arg_1 = NULL,
        .para_arg_2 = NULL
      };

      fd_hash_t out_hash = {0};
      fd_accounts_hash( ctx->slot_ctx->funk,
                        fd_bank_slot_get( ctx->slot_ctx->bank ),
                        &out_hash,
                        ctx->runtime_spad,
                        fd_bank_features_query( ctx->slot_ctx->bank ),
                        &exec_para_ctx,
                        NULL );
      FD_LOG_NOTICE(( "Done computing epoch account hash (%s)", FD_BASE58_ENC_32_ALLOCA( &out_hash ) ));

      fd_bank_epoch_account_hash_set( ctx->slot_ctx->bank, out_hash );

      fd_bank_eah_start_slot_set( ctx->slot_ctx->bank, FD_SLOT_NULL );
    }
  }

}

static void
funk_and_txncache_publish( fd_replay_tile_ctx_t * ctx, ulong wmk, fd_funk_txn_xid_t const * xid ) {

  FD_LOG_DEBUG(( "Entering funk_and_txncache_publish for wmk=%lu", wmk ));

  if( xid->ul[0] != wmk ) {
    FD_LOG_CRIT(( "Invariant violation: xid->ul[0] != wmk %lu %lu", xid->ul[0], wmk ));
  }

  /* Handle updates to funk and the status cache. */

  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_map_t * txn_map     = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_t *     to_root_txn = fd_funk_txn_query( xid, txn_map );
  if( FD_UNLIKELY( !to_root_txn ) ) {
    FD_LOG_ERR(( "Unable to find funk transaction for xid %lu", xid->ul[0] ));
  }
  fd_funk_txn_t *   rooted_txn  = NULL;
  fd_funk_txn_end_read( ctx->funk );

  txncache_publish( ctx, to_root_txn, rooted_txn );

  funk_publish( ctx, to_root_txn, wmk );

  if( FD_UNLIKELY( ctx->capture_ctx ) ) {
    fd_runtime_checkpt( ctx->capture_ctx, ctx->slot_ctx, wmk );
  }

}

static void
restore_slot_ctx( fd_replay_tile_ctx_t * ctx,
                  ulong                  chunk ) {
  /* Use the full snapshot manifest to initialize the slot context */
  uchar * slot_ctx_mem        = fd_spad_alloc_check( ctx->runtime_spad,
                                                     FD_EXEC_SLOT_CTX_ALIGN,
                                                     FD_EXEC_SLOT_CTX_FOOTPRINT );
  ctx->slot_ctx               = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  ctx->slot_ctx->banks        = ctx->banks;
  ctx->slot_ctx->bank         = fd_banks_get_bank( ctx->banks, 0UL );

  ctx->slot_ctx->funk         = ctx->funk;
  ctx->slot_ctx->status_cache = ctx->status_cache;

  fd_solana_manifest_global_t * manifest_global
    = (fd_solana_manifest_global_t *)fd_chunk_to_laddr( fd_wksp_containing( ctx->manifest_dcache ), chunk );
  fd_exec_slot_ctx_t * recovered_slot_ctx = fd_exec_slot_ctx_recover( ctx->slot_ctx,
                                                                      manifest_global,
                                                                      ctx->runtime_spad );

  if( !recovered_slot_ctx ) {
    FD_LOG_ERR(( "Failed to restore slot context from snapshot manifest!" ));
  }
}

static void
kickoff_repair_orphans( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  fd_blockstore_init( ctx->blockstore,
                      ctx->blockstore_fd,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      fd_bank_slot_get( ctx->slot_ctx->bank ) );

  fd_fseq_update( ctx->published_wmark, fd_bank_slot_get( ctx->slot_ctx->bank ) );
  publish_stake_weights( ctx, stem, ctx->slot_ctx );
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

  {
    NOTIFY_START;
    msg->type                        = FD_REPLAY_SLOT_TYPE;
    msg->slot_exec.slot              = curr_slot;
    msg->slot_exec.parent            = fd_bank_parent_slot_get( ctx->slot_ctx->bank );
    msg->slot_exec.root              = fd_fseq_query( ctx->published_wmark );
    msg->slot_exec.height            = block_entry_block_height;
    msg->slot_exec.transaction_count = fd_bank_txn_count_get( ctx->slot_ctx->bank );
    msg->slot_exec.shred_cnt = fd_bank_shred_cnt_get( ctx->slot_ctx->bank );

    msg->slot_exec.bank_hash = fd_bank_bank_hash_get( ctx->slot_ctx->bank );

    fd_block_hash_queue_global_t const * block_hash_queue = fd_bank_block_hash_queue_query( ctx->slot_ctx->bank );
    fd_hash_t * last_hash = fd_block_hash_queue_last_hash_join( block_hash_queue );
    msg->slot_exec.block_hash = *last_hash;

    memcpy( &msg->slot_exec.identity, ctx->validator_identity_pubkey, sizeof( fd_pubkey_t ) );
    msg->slot_exec.ts = tsorig;
    NOTIFY_END;
  }
  fd_bank_shred_cnt_set( ctx->slot_ctx->bank, 0UL );

  FD_TEST( curr_slot == fd_bank_slot_get( ctx->slot_ctx->bank ) );

#undef NOTIFY_START
#undef NOTIFY_END
  notify_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: notify_slot_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)notify_time_ns * 1e-6));

  if( ctx->plugin_out->mem ) {
    /*
    fd_replay_complete_msg_t msg2 = {
      .slot = curr_slot,
      .total_txn_count = ctx->slot_ctx->txn_count,
      .nonvote_txn_count = ctx->slot_ctx->nonvote_txn_count,
      .failed_txn_count = ctx->slot_ctx->failed_txn_count,
      .nonvote_failed_txn_count = ctx->slot_ctx->nonvote_failed_txn_count,
      .compute_units = ctx->slot_ctx->total_compute_units_used,
      .transaction_fee = ctx->slot_ctx->slot_bank.collected_execution_fees,
      .priority_fee = ctx->slot_ctx-2842>slot_bank.collected_priority_fees,
      .parent_slot = fd_bank_parent_slot_get( ctx->slot_ctx->bank ),
    };
    */

    ulong msg[11];
    msg[ 0 ] = fd_bank_slot_get( ctx->slot_ctx->bank );
    msg[ 1 ] = fd_bank_txn_count_get( ctx->slot_ctx->bank );
    msg[ 2 ] = fd_bank_nonvote_txn_count_get( ctx->slot_ctx->bank );
    msg[ 3 ] = fd_bank_failed_txn_count_get( ctx->slot_ctx->bank );
    msg[ 4 ] = fd_bank_nonvote_failed_txn_count_get( ctx->slot_ctx->bank );
    msg[ 5 ] = fd_bank_total_compute_units_used_get( ctx->slot_ctx->bank );
    msg[ 6 ] = fd_bank_execution_fees_get( ctx->slot_ctx->bank );
    msg[ 7 ] = fd_bank_priority_fees_get( ctx->slot_ctx->bank );
    msg[ 8 ] = 0UL; /* todo ... track tips */
    msg[ 9 ] = fd_bank_parent_slot_get( ctx->slot_ctx->bank );
    msg[ 10 ] = 0UL;  /* todo ... max compute units */
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_COMPLETED, (uchar const *)msg, sizeof(msg) );
  }
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx,
                     fd_stem_context_t *    stem ) {
  /* Do not modify order! */

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->slot_ctx,
                                              NULL,
                                              ctx->exec_spads,
                                              ctx->exec_spad_cnt,
                                              ctx->runtime_spad );

  ulong snapshot_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    /* Genesis-specific setup. */
    /* FIXME: This branch does not set up a new block exec ctx
       properly. Needs to do whatever prepare_new_block_execution
       does, but just hacking that in breaks stuff. */
    fd_runtime_update_leaders( ctx->slot_ctx->bank,
                               fd_bank_slot_get( ctx->slot_ctx->bank ),
                               ctx->runtime_spad );

    fd_bank_parent_slot_set( ctx->slot_ctx->bank, 0UL );

    ulong hashcnt_per_slot = fd_bank_hashes_per_tick_get( ctx->slot_ctx->bank ) * fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );
    fd_hash_t * poh = fd_bank_poh_modify( ctx->slot_ctx->bank );
    while(hashcnt_per_slot--) {
      fd_sha256_hash( poh->hash, 32UL, poh->hash );
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

    snapshot_slot = 1UL;

    /* Now setup exec tiles for execution */
    for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
      ctx->exec_ready[ i ] = EXEC_TXN_READY;
    }
  }

  ctx->snapshot_slot = snapshot_slot;

  /* Initialize consensus structures post-snapshot */

  fd_fork_t * snapshot_fork = fd_forks_init( ctx->forks, fd_bank_slot_get( ctx->slot_ctx->bank ) );
  if( FD_UNLIKELY( !snapshot_fork ) ) {
    FD_LOG_CRIT(( "Failed to initialize snapshot fork" ));
  }

  fd_stakes_global_t const *        stakes        = fd_bank_stakes_locking_query( ctx->slot_ctx->bank );
  fd_vote_accounts_global_t const * vote_accounts = &stakes->vote_accounts;

  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );

  /* Send to tower tile */

  if( FD_LIKELY( ctx->tower_out_idx!=ULONG_MAX ) ) {
    uchar * chunk_laddr = fd_chunk_to_laddr( ctx->tower_out_mem, ctx->tower_out_chunk );
    ulong   off         = 0;
    for( fd_vote_accounts_pair_global_t_mapnode_t * curr = fd_vote_accounts_pair_global_t_map_minimum( vote_accounts_pool, vote_accounts_root );
        curr;
        curr = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, curr ) ) {

      if( FD_UNLIKELY( curr->elem.stake > 0UL ) ) {
        memcpy( chunk_laddr + off, &curr->elem.key, sizeof(fd_pubkey_t) );
        off += sizeof(fd_pubkey_t);

        memcpy( chunk_laddr + off, &curr->elem.stake, sizeof(ulong) );
        off += sizeof(ulong);
      }
    }
    fd_stem_publish( stem, ctx->tower_out_idx, snapshot_slot << 32UL | UINT_MAX, ctx->tower_out_chunk, off, 0UL, (ulong)fd_log_wallclock(), (ulong)fd_log_wallclock() );
  }

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;
  for( fd_vote_accounts_pair_global_t_mapnode_t * curr = fd_vote_accounts_pair_global_t_map_minimum( vote_accounts_pool, vote_accounts_root );
       curr;
       curr = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, curr ) ) {
    bank_hash_cmp->total_stake += curr->elem.stake;
  }
  bank_hash_cmp->watermark = snapshot_slot;

  fd_bank_stakes_end_locking_query( ctx->slot_ctx->bank );

  ulong root = snapshot_slot;
  if( FD_LIKELY( root > fd_fseq_query( ctx->published_wmark ) ) ) {

    /* The watermark has advanced likely because we loaded an
       incremental snapshot that was downloaded just-in-time.  We had
       kicked off repair with an older incremental snapshot, and so now
       we have to prune the relevant data structures, so replay can
       start from the latest frontier.

       No funk_and_txncache_publish( ctx, wmark, &xid ); because there
       are no funk txns to publish, and all rooted slots have already
       been registered in the txncache when we loaded the snapshot. */

    if( FD_LIKELY( ctx->blockstore ) ) fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, root );
    if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, root );

    fd_fseq_update( ctx->published_wmark, root );
  }

  /* Now that the snapshot(s) are done loading, we can mark all of the
     exec tiles as ready. */
  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    if( ctx->exec_ready[ i ] == EXEC_TXN_BUSY ) {
      ctx->exec_ready[ i ] = EXEC_TXN_READY;
    }
  }


  FD_LOG_NOTICE(( "snapshot slot %lu", snapshot_slot ));
}

static void
init_from_snapshot( fd_replay_tile_ctx_t * ctx,
                    fd_stem_context_t *    stem ) {
  fd_features_restore( ctx->slot_ctx, ctx->runtime_spad );
  fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );

  fd_slot_lthash_t const * lthash = fd_bank_lthash_query( ctx->slot_ctx->bank );
  if( fd_lthash_is_zero( (fd_lthash_value_t * )lthash ) ) {
    /* calculate and send lthash to exec tiles */
    fd_exec_para_cb_ctx_t exec_para_ctx_snap = {
      .func       = snapshot_hash_tiles_cb,
      .para_arg_1 = ctx,
      .para_arg_2 = stem,
    };

    fd_hash_t accounts_hash;
    fd_lthash_value_t lthash_buf;
    fd_lthash_zero(&lthash_buf);
    fd_snapshot_hash( ctx->slot_ctx,
                      &accounts_hash,
                      1,
                      ctx->runtime_spad,
                      &exec_para_ctx_snap,
                      &lthash_buf );
    fd_slot_lthash_t * lthash_val = fd_bank_lthash_modify( ctx->slot_ctx->bank );
    fd_memcpy( (fd_lthash_value_t *)fd_type_pun(lthash_val->lthash), &lthash_buf, sizeof(lthash_buf) );
  }

  fd_runtime_update_leaders( ctx->slot_ctx->bank,
    fd_bank_slot_get( ctx->slot_ctx->bank ),
    ctx->runtime_spad );

  fd_runtime_read_genesis( ctx->slot_ctx,
                           ctx->genesis,
                           1,
                           ctx->capture_ctx,
                           ctx->runtime_spad );
  /* We call this after fd_runtime_read_genesis, which sets up the
  slot_bank needed in blockstore_init. */
  /* FIXME: We should really only call this once. */
  fd_blockstore_init( ctx->blockstore,
                      ctx->blockstore_fd,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      fd_bank_slot_get( ctx->slot_ctx->bank ) );
  init_after_snapshot( ctx, stem );

  if( ctx->plugin_out->mem && strlen( ctx->genesis ) > 0 ) {
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_GENESIS_HASH_KNOWN, fd_bank_genesis_hash_query( ctx->slot_ctx->bank )->hash, sizeof(fd_hash_t) );
  }

  // Tell the world about the current activate features
  fd_features_t const * features = fd_bank_features_query( ctx->slot_ctx->bank );
  fd_memcpy( &ctx->runtime_public->features, features, sizeof(ctx->runtime_public->features) );

  /* Publish slot notifs */
  ulong curr_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  ulong block_entry_height = fd_bank_block_height_get( ctx->slot_ctx->bank );

  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  FD_TEST( ctx->slot_ctx );
}

static void
on_snapshot_message( fd_replay_tile_ctx_t * ctx,
                     fd_stem_context_t *    stem,
                     ulong                  chunk,
                     ulong                  sig ) {
  if( sig==FD_SNAPSHOT_DONE ) {
    /* An end of message notification indicates the snapshot is loaded.
       Replay is able to start executing from this point onwards. */
    /* TODO: replay should finish booting. Could make replay a
       state machine and set the state here accordingly. */
    FD_LOG_INFO(("Snapshot loaded, replay can start executing"));
    ctx->snapshot_init_done = 1;
    init_from_snapshot( ctx, stem );
    return;
  }

  switch( sig ) {
    case FD_FULL_SNAPSHOT_MANIFEST: {
      /* A snapshot manifest message contains information needed to
       initialize a bank to start replaying slots from the snapshot slot. */
      FD_LOG_INFO(("Received full snapshot manifest message"));
      break;
    }
    case FD_INCREMENTAL_SNAPSHOT_MANIFEST: {
      FD_LOG_INFO(("Received incremental snapshot manifest message"));
      return;
    }
    case FD_FULL_SNAPSHOT_MANIFEST_EXTERNAL:
    case FD_INCREMENTAL_SNAPSHOT_MANIFEST_EXTERNAL: {
      /* We may either receive a full snapshot manifest or an
         incremental snapshot manifest.  Note that this external message
         id is only used temporarily because replay cannot yet receive
         the firedancer-internal snapshot manifest message. */
      restore_slot_ctx( ctx, chunk );
      /* kick off repair orphans */
      kickoff_repair_orphans( ctx, stem );
      break;
    }
    default: {
      FD_LOG_WARNING(("Received unknown snapshot message with sig %lu", sig ));
      return;
    }
  }

  return;
}

static void
during_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)ctl;

  if( FD_LIKELY( in_idx==SNAP_IN_IDX ) ) {
    ctx->_snap_out_chunk = chunk;
  }
}

static void
after_frag( fd_replay_tile_ctx_t *   ctx,
            ulong                    in_idx,
            ulong                    seq FD_PARAM_UNUSED,
            ulong                    sig,
            ulong                    sz FD_PARAM_UNUSED,
            ulong                    tsorig FD_PARAM_UNUSED,
            ulong                    tspub FD_PARAM_UNUSED,
            fd_stem_context_t *      stem FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==ctx->tower_in_idx ) ) {
    ulong root = sig;

    if( FD_LIKELY( root <= fd_fseq_query( ctx->published_wmark ) ) ) return;
    FD_LOG_NOTICE(( "advancing root %lu => %lu", fd_fseq_query( ctx->published_wmark ), root ));

    if( FD_UNLIKELY( ctx->slot_ctx->bank->slot==root ) ) {
      FD_LOG_CRIT(( "invariant violation: root %lu is the same as the current slot %lu", root, ctx->slot_ctx->bank->slot ));
    }

    ctx->root = root;
    if( FD_LIKELY( ctx->blockstore ) ) fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, root );
    if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, root );
    if( FD_LIKELY( ctx->funk ) ) { fd_funk_txn_xid_t xid = { .ul = { root, root } }; funk_and_txncache_publish( ctx, root, &xid ); }
    if( FD_LIKELY( ctx->banks ) ) fd_banks_publish( ctx->banks, root );

    fd_fseq_update( ctx->published_wmark, root );
  } else if( in_idx==SNAP_IN_IDX ) {
    on_snapshot_message( ctx, stem, ctx->_snap_out_chunk, sig );
  }
}

__attribute__((unused)) static void
init_poh( fd_replay_tile_ctx_t * ctx ) {
  FD_LOG_INFO(( "sending init msg" ));

  FD_LOG_WARNING(( "hashes_per_tick: %lu, ticks_per_slot: %lu",
                   fd_bank_hashes_per_tick_get( ctx->slot_ctx->bank ),
                   fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank ) ));

  fd_replay_out_link_t * bank_out = &ctx->bank_out[ 0UL ];
  fd_poh_init_msg_t * msg = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk ); // FIXME: msg is NULL
  msg->hashcnt_per_tick = fd_bank_hashes_per_tick_get( ctx->slot_ctx->bank );
  msg->ticks_per_slot   = fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );
  msg->tick_duration_ns = (ulong)(fd_bank_ns_per_slot_get( ctx->slot_ctx->bank )) / fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );

  fd_block_hash_queue_global_t * bhq       = (fd_block_hash_queue_global_t *)&ctx->slot_ctx->bank->block_hash_queue[0];
  fd_hash_t *                    last_hash = fd_block_hash_queue_last_hash_join( bhq );
  if( last_hash ) {
    memcpy(msg->last_entry_hash, last_hash, sizeof(fd_hash_t));
  } else {
    memset(msg->last_entry_hash, 0UL, sizeof(fd_hash_t));
  }
  msg->tick_height = fd_bank_slot_get( ctx->slot_ctx->bank ) * msg->ticks_per_slot;

  ulong sig = fd_disco_replay_old_sig( fd_bank_slot_get( ctx->slot_ctx->bank ), REPLAY_FLAG_INIT );
  fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, sizeof(fd_poh_init_msg_t), 0UL, 0UL, 0UL );
  bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, sizeof(fd_poh_init_msg_t), bank_out->chunk0, bank_out->wmark );
  bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  ctx->poh_init_done = 1;
}

static void
publish_votes_to_plugin( fd_replay_tile_ctx_t * ctx,
                         fd_stem_context_t *    stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->votes_plugin_out->mem, ctx->votes_plugin_out->chunk );

  ulong bank_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &bank_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY ( !fork  ) ) return;

  fd_vote_accounts_global_t const *          epoch_stakes      = fd_bank_epoch_stakes_locking_query( ctx->slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( epoch_stakes );
  fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( epoch_stakes );

  ulong i = 0;
  FD_SPAD_FRAME_BEGIN( ctx->runtime_spad ) {
  for( fd_vote_accounts_pair_global_t_mapnode_t const * n = fd_vote_accounts_pair_global_t_map_minimum_const( epoch_stakes_pool, epoch_stakes_root );
       n && i < FD_CLUSTER_NODE_CNT;
       n = fd_vote_accounts_pair_global_t_map_successor_const( epoch_stakes_pool, n ) ) {
    if( n->elem.stake == 0 ) continue;

    uchar * data     = (uchar *)&n->elem.value + n->elem.value.data_offset;
    ulong   data_len = n->elem.value.data_len;

    int err;
    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, ctx->runtime_spad,
        data,
        data_len,
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unexpected failure in decoding vote state %d", err ));
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
    fd_clock_timestamp_votes_global_t const * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_query( ctx->slot_ctx->bank );
    fd_clock_timestamp_vote_t_mapnode_t * timestamp_votes_root  = fd_clock_timestamp_votes_votes_root_join( clock_timestamp_votes );
    fd_clock_timestamp_vote_t_mapnode_t * timestamp_votes_pool  = fd_clock_timestamp_votes_votes_pool_join( clock_timestamp_votes );

    fd_clock_timestamp_vote_t_mapnode_t * res = fd_clock_timestamp_vote_t_map_find( timestamp_votes_pool, timestamp_votes_root, &query );

    fd_vote_update_msg_t * msg = (fd_vote_update_msg_t *)(dst + sizeof(ulong) + i*112U);
    memset( msg, 0, 112U );
    memcpy( msg->vote_pubkey, n->elem.key.uc, sizeof(fd_pubkey_t) );
    memcpy( msg->node_pubkey, node_pubkey.uc, sizeof(fd_pubkey_t) );
    msg->activated_stake = n->elem.stake;
    msg->last_vote       = res == NULL ? 0UL : res->elem.slot;
    msg->root_slot       = root_slot;
    msg->epoch_credits   = epoch_credits;
    msg->commission      = (uchar)commission;
    msg->is_delinquent   = (uchar)fd_int_if(fd_bank_slot_get( ctx->slot_ctx->bank ) >= 128UL, msg->last_vote <= fd_bank_slot_get( ctx->slot_ctx->bank ) - 128UL, msg->last_vote == 0);
    ++i;
    fd_bank_clock_timestamp_votes_end_locking_query( ctx->slot_ctx->bank );
  }
  } FD_SPAD_FRAME_END;

  fd_bank_epoch_stakes_end_locking_query( ctx->slot_ctx->bank );

  *(ulong *)dst = i;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->votes_plugin_out->idx, FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE, ctx->votes_plugin_out->chunk, 0, 0UL, 0UL, tspub );
  ctx->votes_plugin_out->chunk = fd_dcache_compact_next( ctx->votes_plugin_out->chunk, 8UL + 40200UL*(58UL+12UL*34UL), ctx->votes_plugin_out->chunk0, ctx->votes_plugin_out->wmark );
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
init_from_genesis( fd_replay_tile_ctx_t * ctx,
                   fd_stem_context_t *    stem ) {
  fd_runtime_read_genesis( ctx->slot_ctx,
                           ctx->genesis,
                           0,
                           ctx->capture_ctx,
                           ctx->runtime_spad );

  /* We call this after fd_runtime_read_genesis, which sets up the
  slot_bank needed in blockstore_init. */
  /* FIXME: We should really only call this once. */
  fd_blockstore_init( ctx->blockstore,
                      ctx->blockstore_fd,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      fd_bank_slot_get( ctx->slot_ctx->bank ) );
  init_after_snapshot( ctx, stem );

  if( ctx->plugin_out->mem && strlen( ctx->genesis ) > 0 ) {
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_GENESIS_HASH_KNOWN, fd_bank_genesis_hash_query( ctx->slot_ctx->bank )->hash, sizeof(fd_hash_t) );
  }

  // Tell the world about the current activate features
  fd_features_t const * features = fd_bank_features_query( ctx->slot_ctx->bank );
  fd_memcpy( &ctx->runtime_public->features, features, sizeof(ctx->runtime_public->features) );

  /* Publish slot notifs */
  ulong curr_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  ulong block_entry_height = 0;

  /* Block after genesis has a height of 1.
     TODO: We should be able to query slot 1 block_map entry to get this
     (using the above for loop), but blockstore/fork setup on genesis is
     broken for now. */
  block_entry_height = 1UL;
  init_poh( ctx );

  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  FD_TEST( ctx->slot_ctx );
}

static void
handle_new_slot( fd_replay_tile_ctx_t * ctx,
                 fd_stem_context_t *    stem,
                 ulong                  slot,
                 ulong                  parent_slot ) {

  /* We need to handle logic that creates a bank and funk txn since
     we are starting to execute a new slot. We must also manage the
     forks data structure to reflect that this slot is now being
     executed. */

  /* First, update fd_forks_t */

  /* Make sure that the slot is not already in the frontier. */
  if( FD_UNLIKELY( fd_fork_frontier_ele_query(
      ctx->forks->frontier,
      &slot,
      NULL,
      ctx->forks->pool ) ) ) {
    FD_LOG_CRIT(( "invariant violation: child slot %lu was already in the frontier", slot ) );
  }

  /* This means we want to execute a slice on a new slot. This means
      we have to update our forks and create a new bank/funk_txn. */
  fd_fork_t * fork = fd_forks_prepare(
      ctx->forks,
      parent_slot,
      ctx->funk,
      ctx->runtime_spad );
  if( FD_UNLIKELY( !fork ) ) {
    FD_LOG_CRIT(( "invariant violation: failed to prepare fork for slot: %lu", slot ));
  }

  /* We need to update the fork's position in the map. This means
      we have to remove it from the map, update its key and reinsert
      into the frontier map. */
  fd_fork_t * fork_map_ele = fd_fork_frontier_ele_remove(
      ctx->forks->frontier,
      &fork->slot,
      NULL,
      ctx->forks->pool );
  if( FD_UNLIKELY( !fork_map_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: failed to remove fork for slot: %lu", slot ));
  }

  /* Update the values for the child */
  fork_map_ele->slot    = slot;
  fork_map_ele->end_idx = UINT_MAX;

  fd_fork_frontier_ele_insert( ctx->forks->frontier, fork_map_ele, ctx->forks->pool );

  if( FD_UNLIKELY( fork!=fork_map_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: fork != new_fork for slot: %lu", slot ));
  }

  /* Second, clone the bank from the parent. */

  ctx->slot_ctx->bank = fd_banks_clone_from_parent( ctx->banks, slot, parent_slot );
  if( FD_UNLIKELY( !ctx->slot_ctx->bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL curr_slot: %lu, parent_slot: %lu", slot, parent_slot ));
  }

  /* Third, create a new funk txn for the slot. */

  fd_funk_txn_start_write( ctx->funk );

  fd_funk_txn_xid_t xid = { .ul = { slot, slot } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_slot } };

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn_map is NULL for slot %lu", slot ));
  }

  fd_funk_txn_t * parent_txn = fd_funk_txn_query( &parent_xid, txn_map );
  if( FD_UNLIKELY( !parent_txn && parent_slot!=ctx->snapshot_slot ) ) {
    FD_LOG_CRIT(( "parent_txn is NULL for slot %lu", parent_slot ));
  }

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( ctx->funk, parent_txn, &xid, 1 );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn is NULL for slot %lu", slot ));
  }

  ctx->slot_ctx->funk_txn = funk_txn;

  fd_funk_txn_end_write( ctx->funk );

  /* Now update any required runtime state and handle an epoch
      boundary change. */

  fd_bank_parent_slot_set( ctx->slot_ctx->bank, parent_slot );

  fd_bank_tick_height_set( ctx->slot_ctx->bank, fd_bank_max_tick_height_get( ctx->slot_ctx->bank ) );

  ulong * max_tick_height = fd_bank_max_tick_height_modify( ctx->slot_ctx->bank );
  ulong   ticks_per_slot  = fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height(ticks_per_slot, slot, max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
  }

  fd_bank_enable_exec_recording_set( ctx->slot_ctx->bank, ctx->tx_metadata_storage );

  int is_epoch_boundary = 0;
  fd_runtime_block_pre_execute_process_new_epoch(
      ctx->slot_ctx,
      NULL,
      ctx->exec_spads,
      ctx->exec_spad_cnt,
      ctx->runtime_spad,
      &is_epoch_boundary );
  if( FD_UNLIKELY( is_epoch_boundary ) ) {
    publish_stake_weights( ctx, stem, ctx->slot_ctx );
  }

  int res = fd_runtime_block_execute_prepare( ctx->slot_ctx, ctx->runtime_spad );
  if( FD_UNLIKELY( res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    FD_LOG_CRIT(( "block prep execute failed" ));
  }
}

static void
handle_prev_slot( fd_replay_tile_ctx_t * ctx,
                  ulong                  slot,
                  ulong                  parent_slot ) {
  /* Because a fork already exists for the fork we are attempting to
     execute, we just need to update the slot ctx's handles to
     the bank and funk txn. */

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( !fork ) ) {
    FD_LOG_CRIT(( "invariant violation: fork is NULL for slot %lu", slot ));
  }

  FD_LOG_NOTICE(( "switching to executing slot: %lu (parent: %lu) at batch: %u", slot, parent_slot, fork->end_idx ));

  ctx->slot_ctx->bank = fd_banks_get_bank( ctx->banks, slot );
  if( FD_UNLIKELY( !ctx->slot_ctx->bank ) ) {
    FD_LOG_CRIT(( "invariant violation: fork is non-NULL and bank is NULL for slot %lu", slot ));
  }

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_xid_t   xid     = { .ul = { slot, slot } };
  ctx->slot_ctx->funk_txn     = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !ctx->slot_ctx->funk_txn ) ) {
    FD_LOG_CRIT(( "invariant violation: fork is non-NULL and funk_txn is NULL for slot %lu", slot ));
  }
}

static void
handle_slot_change( fd_replay_tile_ctx_t * ctx,
                    fd_stem_context_t *    stem,
                    ulong                  slot,
                    ulong                  parent_slot ) {
  /* This is an edge case related to pack. The parent fork might
     already be in the frontier and currently executing (ie.
     fork->frozen = 0). */
  fd_fork_t * parent_fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &parent_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( parent_fork && !!parent_fork->lock ) ) {
    FD_LOG_CRIT(( "invariant violation: parent fork is locked for slot %lu", slot ));
  }

  ulong turbine_slot = fd_fseq_query( ctx->turbine_slot );
  FD_LOG_NOTICE(( "\n\n[Replay]\n"
    "slot:            %lu\n"
    "current turbine: %lu\n"
    "slots behind:    %lu\n"
    "live:            %d\n",
    slot,
    turbine_slot,
    turbine_slot - slot,
    (turbine_slot-slot)<5UL ));

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &slot, NULL, ctx->forks->pool );
  if( !!fork ) {
    FD_LOG_NOTICE(( "switching from slot: %lu to executing on a different slot: %lu", fd_bank_slot_get( ctx->slot_ctx->bank ), slot ));
    /* This means we are switching back to a slot we have already
       started executing (we have executed at least 1 slice from the
       slot we are switching to). */
    handle_prev_slot( ctx, slot, parent_slot );
  } else {
    /* This means we are switching to a new slot. */
    handle_new_slot( ctx, stem, slot, parent_slot );
  }

  if( ctx->capture_ctx ) {
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, slot );
  }
}

static void
handle_new_slice( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  /* If there are no slices in slice deque, then there is nothing to
     execute. */
  if( FD_UNLIKELY( fd_exec_slice_cnt( ctx->exec_slice_deque )==0UL ) ) {
    return;
  }

  /* Pop the head of the slice deque and do some basic sanity checks. */
  ulong  sig           = fd_exec_slice_pop_head( ctx->exec_slice_deque );
  ulong  slot          = fd_disco_repair_replay_sig_slot( sig );
  ushort parent_off    = fd_disco_repair_replay_sig_parent_off( sig );
  uint   data_cnt      = fd_disco_repair_replay_sig_data_cnt( sig );
  int    slot_complete = fd_disco_repair_replay_sig_slot_complete( sig );
  ulong  parent_slot   = slot - parent_off;

  if( FD_UNLIKELY( slot<fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). earlier than our watermark %lu.", slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ));
    return;
  }

  if( FD_UNLIKELY( parent_slot<fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). parent slot is earlier than our watermark %lu.", slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ) );
    return;
  }

  /* If the slot of the slice we are about to execute is different than
     the current slot, then we need to handle it. There are two cases:
     1. We have already executed at least one slice from the slot.
        Then we just need to query for the correct database handle,
        fork, and bank.
     2. We need to create a database txn, initialize forks, and clone
        a bank. */
  if( FD_UNLIKELY( slot!=fd_bank_slot_get( ctx->slot_ctx->bank ) ) ) {
    handle_slot_change( ctx, stem, slot, parent_slot );
  }

  /* At this point, our runtime state has been updated correctly. We
     need to update the current fork with the range of shred indices
     that we are about to execute. We also need to populate the slice's
     metadata into the slice_exec_ctx. */
  fd_fork_t * current_fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( !current_fork ) ) {
    FD_LOG_CRIT(( "invariant violation: current_fork is NULL for slot %lu", slot ));
  }

  uint start_idx = current_fork->end_idx + 1U;
  uint end_idx   = start_idx + data_cnt - 1U;
  ulong slice_sz = 0UL;

  current_fork->end_idx = end_idx;

  int err = fd_blockstore_slice_query(
      ctx->blockstore,
      slot,
      start_idx,
      end_idx,
      FD_SLICE_MAX,
      ctx->slice_exec_ctx.buf,
      &slice_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "invariante violation: unable to query blockstore for slot %lu shred indices [%u,%u]", slot, start_idx, end_idx ));
  }

  fd_slice_exec_begin( &ctx->slice_exec_ctx, slice_sz, slot_complete );
  fd_bank_shred_cnt_set( ctx->slot_ctx->bank, fd_bank_shred_cnt_get( ctx->slot_ctx->bank ) + data_cnt );
}

static ulong
get_free_exec_tiles( fd_replay_tile_ctx_t * ctx, uchar * exec_free_idx ) {
  ulong cnt=0UL;
  for( uchar i=0; i<ctx->exec_cnt; i++ ) {
    if( ctx->exec_ready[ i ]==EXEC_TXN_READY) {
      exec_free_idx[ cnt ] = i;
      cnt++;
    }
  }
  return cnt;
}

static void
exec_slice_fini_slot( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( ctx->slice_exec_ctx.buf + ctx->slice_exec_ctx.last_mblk_off );
  fd_hash_t * poh = fd_bank_poh_modify( ctx->slot_ctx->bank );
  memcpy( poh, hdr->hash, sizeof(fd_hash_t) );

  /* Reset ctx for next slot */
  fd_slice_exec_reset( &ctx->slice_exec_ctx );

  /* do hashing */

  fd_runtime_block_info_t runtime_block_info[1];
  runtime_block_info->signature_cnt = fd_bank_signature_count_get( ctx->slot_ctx->bank );

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

  ulong curr_slot = fd_bank_slot_get( ctx->slot_ctx->bank );

  ulong block_entry_height = fd_bank_block_height_get( ctx->slot_ctx->bank );
  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  ctx->blockstore->shmem->lps = curr_slot;

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( !fork ) ) {
    FD_LOG_CRIT(( "invariant violation: fork is NULL for slot %lu", curr_slot ));
  }
  fork->lock = 0;

  if( FD_LIKELY( ctx->tower_out_idx!=ULONG_MAX && !ctx->read_only ) ) {
    uchar * chunk_laddr = fd_chunk_to_laddr( ctx->tower_out_mem, ctx->tower_out_chunk );
    fd_hash_t const * bank_hash = fd_bank_bank_hash_query( ctx->slot_ctx->bank );
    fd_block_hash_queue_global_t * block_hash_queue = (fd_block_hash_queue_global_t *)&ctx->slot_ctx->bank->block_hash_queue[0];
    fd_hash_t * last_hash = fd_block_hash_queue_last_hash_join( block_hash_queue );

    memcpy( chunk_laddr, bank_hash, sizeof(fd_hash_t) );
    memcpy( chunk_laddr+sizeof(fd_hash_t), last_hash, sizeof(fd_hash_t) );
    fd_stem_publish( stem, ctx->tower_out_idx, fd_bank_slot_get( ctx->slot_ctx->bank ) << 32UL | fd_bank_parent_slot_get( ctx->slot_ctx->bank ), ctx->tower_out_chunk, sizeof(fd_hash_t) * 2, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
  }

  /**********************************************************************/
  /* Prepare bank for the next execution and write to debugging files   */
  /**********************************************************************/

  ulong prev_slot = fd_bank_slot_get( ctx->slot_ctx->bank );

  fd_bank_execution_fees_set( ctx->slot_ctx->bank, 0UL );

  fd_bank_priority_fees_set( ctx->slot_ctx->bank, 0UL );

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

  fd_hash_t const * bank_hash = fd_bank_bank_hash_query( ctx->slot_ctx->bank );
  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;
  fd_bank_hash_cmp_lock( bank_hash_cmp );
  fd_bank_hash_cmp_insert( bank_hash_cmp, curr_slot, bank_hash, 1, 0 );

  if( ctx->shredcap_out->idx!=ULONG_MAX ) {
    /* TODO: We need some way to define common headers. */
    uchar *           chunk_laddr = fd_chunk_to_laddr( ctx->shredcap_out->mem, ctx->shredcap_out->chunk );
    fd_hash_t const * bank_hash   = fd_bank_bank_hash_query( ctx->slot_ctx->bank );
    ulong             slot        = fd_bank_slot_get( ctx->slot_ctx->bank );
    memcpy( chunk_laddr, bank_hash, sizeof(fd_hash_t) );
    memcpy( chunk_laddr+sizeof(fd_hash_t), &slot, sizeof(ulong) );
    fd_stem_publish( stem, ctx->shredcap_out->idx, 0UL, ctx->shredcap_out->chunk, sizeof(fd_hash_t) + sizeof(ulong), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->shredcap_out->chunk = fd_dcache_compact_next( ctx->shredcap_out->chunk, sizeof(fd_hash_t) + sizeof(ulong), ctx->shredcap_out->chunk0, ctx->shredcap_out->wmark );
  }

  /* Try to move the bank hash comparison watermark forward */
  for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < curr_slot; cmp_slot++ ) {
    if( FD_UNLIKELY( !ctx->enable_bank_hash_cmp ) ) {
      bank_hash_cmp->watermark = cmp_slot;
      break;
    }
    int rc = fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot );
    switch ( rc ) {
      case -1:
        /* Mismatch */
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
}

static void
exec_and_handle_slice( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {
  uchar exec_free_idx[ FD_PACK_MAX_BANK_TILES ];
  ulong free_exec_cnt = get_free_exec_tiles( ctx, exec_free_idx );

  /* If there are no txns left to execute in the microblock and the
     exec tiles are not busy, then we are ready to either start
     executing the next microblock/slice/slot.

     We have to synchronize on the the microblock boundary because we
     only have the guarantee that all transactions within the same
     microblock can be executed in parallel. */
  if( !fd_slice_exec_txn_ready( &ctx->slice_exec_ctx ) && free_exec_cnt==ctx->exec_cnt ) {
    if( fd_slice_exec_microblock_ready( &ctx->slice_exec_ctx ) ) {
      fd_slice_exec_microblock_parse( &ctx->slice_exec_ctx );
    } else if( fd_slice_exec_slice_ready( &ctx->slice_exec_ctx ) ) {
      /* If the current slice was the last one for the slot we need to
         finalize the slot (update bank members/compare bank hash). */
      if( fd_slice_exec_slot_complete( &ctx->slice_exec_ctx ) ) {
        exec_slice_fini_slot( ctx, stem );
      }

      /* Now, we are ready to start executing the next buffered slice. */
      handle_new_slice( ctx, stem );
    }
  }

  /* At this point, we know that we have some quantity of transactions
     in a microblock that we are ready to execute. */
  for( ulong i=0UL; i<free_exec_cnt; i++ ) {

    if( !fd_slice_exec_txn_ready( &ctx->slice_exec_ctx ) ) {
      return;
    }

    ulong exec_idx = exec_free_idx[ i ];

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    /* Parse the transaction from the current slice */
    fd_txn_p_t txn_p;
    fd_slice_exec_txn_parse( &ctx->slice_exec_ctx, &txn_p );

    /* Insert or reverify invoked programs for this epoch, if needed
       FIXME: this should be done during txn parsing so that we don't have to loop
       over all accounts a second time. */
    fd_runtime_update_program_cache( ctx->slot_ctx, &txn_p, ctx->runtime_spad );

    /* Mark the exec tile as busy */
    ctx->exec_ready[ exec_idx ] = EXEC_TXN_BUSY;

    /* Dispatch dcache to exec tile */
    fd_replay_out_link_t *        exec_out = &ctx->exec_out[ exec_idx ];
    fd_runtime_public_txn_msg_t * exec_msg = (fd_runtime_public_txn_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );

    memcpy( &exec_msg->txn, &txn_p, sizeof(fd_txn_p_t) );
    exec_msg->slot = fd_bank_slot_get( ctx->slot_ctx->bank );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, exec_out->idx, EXEC_NEW_TXN_SIG, exec_out->chunk, sizeof(fd_runtime_public_txn_msg_t), 0UL, tsorig, tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_runtime_public_txn_msg_t), exec_out->chunk0, exec_out->wmark );
  }
}

static void
after_credit( fd_replay_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy FD_PARAM_UNUSED ) {
  if( !ctx->snapshot_init_done ) {
    if( ctx->plugin_out->mem ) {
      uchar msg[56];
      fd_memset( msg, 0, sizeof(msg) );
      msg[ 0 ] = 0; // ValidatorStartProgress::Initializing
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
    }

    if( strlen( ctx->genesis )>0 ) {
      init_from_genesis( ctx, stem );
      ctx->snapshot_init_done = 1;
    }

    return;
  }

  /* TODO: Consider moving state management to during_housekeeping */

  /* Check all the writer link fseqs. */
  handle_writer_state_updates( ctx );

  exec_and_handle_slice( ctx, stem );

  long now = fd_log_wallclock();
  if( ctx->votes_plugin_out->mem && FD_UNLIKELY( ( now - ctx->last_plugin_push_time )>PLUGIN_PUBLISH_TIME_NS ) ) {
    ctx->last_plugin_push_time = now;
    publish_votes_to_plugin( ctx, stem );
  }

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
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  FD_LOG_NOTICE(("Starting unprivileged init"));
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( tile->in_cnt < 4 ||
                   strcmp( topo->links[ tile->in_link_id[ PACK_IN_IDX ] ].name, "pack_replay")   ||
                   strcmp( topo->links[ tile->in_link_id[ REPAIR_IN_IDX  ] ].name, "repair_repla" ) ||
                   strcmp( topo->links[ tile->in_link_id[ SNAP_IN_IDX  ] ].name, "snap_out" ) ) ) {
    FD_LOG_ERR(( "replay tile has none or unexpected input links %lu %s %s %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name,
                 topo->links[ tile->in_link_id[ 1 ] ].name,
                 topo->links[ tile->in_link_id[ 2 ] ].name,
                 topo->links[ tile->in_link_id[ 3 ] ].name ));
  }

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    ctx->bmtree[i]           = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  void * slice_buf                    = FD_SCRATCH_ALLOC_APPEND( l, 128UL, FD_SLICE_MAX );
  ulong  scratch_alloc_mem            = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );

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
  /* banks                                                              */
  /**********************************************************************/

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  if( FD_UNLIKELY( banks_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "no banks" ));
  }

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  if( FD_UNLIKELY( !ctx->banks ) ) {
    FD_LOG_ERR(( "failed to join banks" ));
  }
  fd_bank_t * bank = fd_banks_init_bank( ctx->banks, 0UL );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_ERR(( "failed to init bank" ));
  }

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->replay.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /**********************************************************************/
  /* root_slot fseq                                                     */
  /**********************************************************************/

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->published_wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->published_wmark ) );

  /**********************************************************************/
  /* turbine_slot fseq                                                  */
  /**********************************************************************/

  ulong turbine_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turbine_slot" );
  FD_TEST( turbine_slot_obj_id!=ULONG_MAX );
  ctx->turbine_slot = fd_fseq_join( fd_topo_obj_laddr( topo, turbine_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->turbine_slot ) ) FD_LOG_ERR(( "replay tile has no turb_slot fseq" ));

  /**********************************************************************/
  /* TOML paths                                                         */
  /**********************************************************************/

  ctx->blockstore_checkpt  = tile->replay.blockstore_checkpt;
  ctx->tx_metadata_storage = tile->replay.tx_metadata_storage;
  ctx->funk_checkpt        = tile->replay.funk_checkpt;
  ctx->genesis             = tile->replay.genesis;

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
  ctx->exec_cnt = fd_topo_tile_name_cnt( topo, "exec" );
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
  /* joins                                                              */
  /**********************************************************************/

  uchar * bank_hash_cmp_shmem = fd_spad_alloc_check( ctx->runtime_spad, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint() );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_shmem ) );

  fd_cluster_version_t * cluster_version = fd_bank_cluster_version_modify( bank );

  if( FD_UNLIKELY( sscanf( tile->replay.cluster_version, "%u.%u.%u", &cluster_version->major, &cluster_version->minor, &cluster_version->patch )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version, configured as \"%s\"", tile->replay.cluster_version ));
  }

  fd_features_t * features = fd_bank_features_modify( bank );
  fd_features_enable_cleaned_up( features, cluster_version );

  char const * one_off_features[16];
  for (ulong i = 0; i < tile->replay.enable_features_cnt; i++) {
    one_off_features[i] = tile->replay.enable_features[i];
  }
  fd_features_enable_one_offs( features, one_off_features, (uint)tile->replay.enable_features_cnt, 0UL );

  ctx->forks = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );

  /**********************************************************************/
  /* bank_hash_cmp                                                      */
  /**********************************************************************/

  ulong bank_hash_cmp_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bh_cmp" );
  FD_TEST( bank_hash_cmp_obj_id!=ULONG_MAX );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) ) );
  if( FD_UNLIKELY( !ctx->bank_hash_cmp ) ) {
    FD_LOG_ERR(( "failed to join bank_hash_cmp" ));
  }

  /**********************************************************************/
  /* voter                                                              */
  /**********************************************************************/

  memcpy( ctx->validator_identity, fd_keyload_load( tile->replay.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  *ctx->vote_authority = *ctx->validator_identity; /* FIXME */
  memcpy( ctx->vote_acc, fd_keyload_load( tile->replay.vote_account_path, 1 ), sizeof(fd_pubkey_t) );

  ctx->validator_identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, 1 ) );

  /**********************************************************************/
  /* entry batch                                                        */
  /**********************************************************************/

  fd_slice_exec_join( &ctx->slice_exec_ctx );
  ctx->slice_exec_ctx.buf = slice_buf;

  /**********************************************************************/
  /* capture                                                            */
  /**********************************************************************/

  if ( strlen(tile->replay.solcap_capture) > 0 || strlen(tile->replay.dump_proto_dir) > 0 ) {
    ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
  } else {
    ctx->capture_ctx = NULL;
  }

  if( strlen(tile->replay.solcap_capture) > 0 ) {
    ctx->capture_ctx->checkpt_freq = ULONG_MAX;
    ctx->capture_file = fopen( tile->replay.solcap_capture, "w+" );
    if( FD_UNLIKELY( !ctx->capture_file ) ) {
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", tile->replay.solcap_capture, errno, strerror( errno ) ));
    }
    ctx->capture_ctx->capture_txns = 0;
    ctx->capture_ctx->solcap_start_slot = tile->replay.capture_start_slot;
    fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->capture_file );
  }

  if ( strlen(tile->replay.dump_proto_dir) > 0) {
    ctx->capture_ctx->dump_proto_output_dir = tile->replay.dump_proto_dir;
    if (tile->replay.dump_block_to_pb) {
      ctx->capture_ctx->dump_block_to_pb = tile->replay.dump_block_to_pb;
    }
  }

  /**********************************************************************/
  /* bank                                                               */
  /**********************************************************************/

  ctx->bank_cnt = fd_topo_tile_name_cnt( topo, "bank" );
  for( ulong i=0UL; i<(ctx->bank_cnt); i++ ) {
    ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", i );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ctx->bank_busy[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    if( FD_UNLIKELY( !ctx->bank_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));

    fd_replay_out_link_t * poh_out = &ctx->bank_out[ i ];
    fd_topo_link_t  * poh_out_link = &topo->links[ tile->out_link_id[ poh_out->idx+i ] ];
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
  ctx->exec_cnt = fd_topo_tile_name_cnt( topo, "exec" );
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
    ctx->exec_ready[ i ]    = EXEC_TXN_BUSY;
    ctx->prev_ids[ i ]      = FD_EXEC_ID_SENTINEL;

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
  ctx->writer_cnt = fd_topo_tile_name_cnt( topo, "writer" );
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

  /* Setup tower tile input */
  ctx->tower_in_idx = fd_topo_find_tile_in_link( topo, tile, "tower_replay", 0 );
  if( FD_UNLIKELY( ctx->tower_in_idx==ULONG_MAX ) ) FD_LOG_WARNING(( "replay tile is missing tower input link %lu", ctx->tower_in_idx ));

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

  /* Setup shredcap tile output. This link should only exist if the
     shredcap tile has been enabled. */
  ulong replay_shredcap_idx = fd_topo_find_tile_out_link( topo, tile, "replay_scap", 0 );
  if( FD_UNLIKELY( replay_shredcap_idx!=ULONG_MAX ) ) {
    fd_topo_link_t * shredcap_out = &topo->links[ tile->out_link_id[ replay_shredcap_idx ] ];
    FD_TEST( shredcap_out );
    ctx->shredcap_out->idx    = replay_shredcap_idx;
    ctx->shredcap_out->mem    = topo->workspaces[ topo->objs[ shredcap_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->shredcap_out->chunk0 = fd_dcache_compact_chunk0( ctx->shredcap_out->mem, shredcap_out->dcache );
    ctx->shredcap_out->wmark  = fd_dcache_compact_wmark ( ctx->shredcap_out->mem, shredcap_out->dcache, shredcap_out->mtu );
    ctx->shredcap_out->chunk  = ctx->shredcap_out->chunk0;
  } else {
    ctx->shredcap_out->idx    = ULONG_MAX;
  }

  /* Set up stake weights tile output */
  ctx->stake_out->idx        = fd_topo_find_tile_out_link( topo, tile, "stake_out", 0 );
  FD_TEST( ctx->stake_out->idx!=ULONG_MAX );
  fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id[ ctx->stake_out->idx] ];
  ctx->stake_out->mcache     = stake_weights_out->mcache;
  ctx->stake_out->mem        = topo->workspaces[ topo->objs[ stake_weights_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_out->sync       = fd_mcache_seq_laddr     ( ctx->stake_out->mcache );
  ctx->stake_out->depth      = fd_mcache_depth         ( ctx->stake_out->mcache );
  ctx->stake_out->seq        = fd_mcache_seq_query     ( ctx->stake_out->sync );
  ctx->stake_out->chunk0     = fd_dcache_compact_chunk0( ctx->stake_out->mem, stake_weights_out->dcache );
  ctx->stake_out->wmark      = fd_dcache_compact_wmark ( ctx->stake_out->mem, stake_weights_out->dcache, stake_weights_out->mtu );
  ctx->stake_out->chunk      = ctx->stake_out->chunk0;

  ctx->tower_out_idx = fd_topo_find_tile_out_link( topo, tile, "replay_tower", 0 );
  if( FD_LIKELY( ctx->tower_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t * tower_out = &topo->links[ tile->out_link_id[ ctx->tower_out_idx ] ];
    ctx->tower_out_mem         = topo->workspaces[ topo->objs[ tower_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->tower_out_chunk0      = fd_dcache_compact_chunk0( ctx->tower_out_mem, tower_out->dcache );
    ctx->tower_out_wmark       = fd_dcache_compact_wmark ( ctx->tower_out_mem, tower_out->dcache, tower_out->mtu );
    ctx->tower_out_chunk       = ctx->tower_out_chunk0;
    FD_TEST( fd_dcache_compact_is_safe( ctx->tower_out_mem, tower_out->dcache, tower_out->mtu, tower_out->depth ) );
  }

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

  ctx->enable_bank_hash_cmp = tile->replay.enable_bank_hash_cmp;

  /* join dcache from wksp */
  ctx->manifest_dcache = (uchar const *)topo->workspaces[ topo->objs[ tile->replay.manifest_dcache_obj_id ].wksp_id ].wksp;

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

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
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
