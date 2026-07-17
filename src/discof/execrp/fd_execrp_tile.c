#include "../execle/fd_execle_err.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../discof/fd_startup.h"
#include "../../discof/replay/fd_execrp.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_executor.h"
#include "../../flamenco/runtime/tests/fd_dump_pb.h"
#include "../../flamenco/progcache/fd_progcache_user.h"
#include "../../flamenco/log_collector/fd_log_collector_base.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../flamenco/events/fd_event_runtime.h"

#include <time.h>
#include "generated/fd_execrp_tile_seccomp.h"

/* The exec tile is responsible for executing single transactions.  The
   tile receives a parsed transaction (fd_txn_p_t) and an identifier to
   which bank to execute against (index into the bank pool).  With this,
   the exec tile is able to identify the correct bank and accounts
   database fork to execute the transaction against.  The exec tile then
   commits the results of the transaction to the accounts db and makes
   any necessary updates to the bank. */

typedef struct link_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
} link_ctx_t;

struct fd_execrp_tile {
  ulong tile_idx;

  fd_startup_gate_t startup_gate[1];

  /* link-related data structures. */
  link_ctx_t            replay_in[ 1 ];
  link_ctx_t            execrp_replay_out[ 1 ]; /* TODO: Remove with solcap v2 */

  fd_sha512_t           sha_mem[ FD_TXN_ACTUAL_SIG_MAX ];
  fd_sha512_t *         sha_lj[ FD_TXN_ACTUAL_SIG_MAX ];

  /* Capture context for debugging runtime execution. */
  fd_capture_ctx_t *    capture_ctx;
  fd_capture_link_buf_t cap_execrp_out[1];

  /* Protobuf dumping context for debugging runtime execution and
     collecting seed corpora. */
  fd_dump_proto_ctx_t * dump_proto_ctx;
  fd_txn_dump_ctx_t *   txn_dump_ctx;

  fd_banks_t *    banks;
  fd_bank_t *     bank;
  fd_accdb_t *    accdb;
  fd_txncache_t * txncache;
  fd_progcache_t  progcache[1];

  ulong txn_idx;
  ulong slot;
  ulong dispatch_time_comp;

  fd_log_collector_t log_collector;

  fd_txn_in_t  txn_in;
  fd_txn_out_t txn_out;

  fd_runtime_t runtime[1];

  struct {
    ulong sigverify_cnt;
    ulong poh_hash_cnt;

    /* Ticks spent loading txn accounts */
    ulong txn_load_cum_ticks;

    /* Ticks spent validating txn invariants (e.g. status cache, fee payer) */
    ulong txn_check_cum_ticks;

    /* Ticks spent executing a txn (includes any VM time) */
    ulong txn_exec_cum_ticks;

    /* Ticks spent committing a txn (database writes) */
    ulong txn_commit_cum_ticks;

    ulong txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_CNT ];
  } metrics;

  /* If non-zero, emit one runtime_txn event per dispatched txn */
  int report_transaction_diffs;
};

typedef struct fd_execrp_tile fd_execrp_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(   l, alignof(fd_execrp_tile_t),    sizeof(fd_execrp_tile_t)                             );
  l = FD_LAYOUT_APPEND(   l, fd_txncache_align(),          fd_txncache_footprint( tile->execrp.max_live_slots ) );
  l = FD_LAYOUT_APPEND(   l, fd_accdb_align(),             fd_accdb_footprint( tile->execrp.max_live_slots )    );
  l = FD_LAYOUT_APPEND(   l, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT                       );

  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),       fd_capture_ctx_footprint()                           );
  }

  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_dump_proto_ctx_t), sizeof(fd_dump_proto_ctx_t)                          );
    l = FD_LAYOUT_APPEND( l, fd_txn_dump_context_align(),  fd_txn_dump_context_footprint()                      );
    if( FD_UNLIKELY( tile->execrp.dump_instr_to_pb || tile->execrp.dump_syscall_to_pb || tile->execrp.dump_txn_to_pb ) ) {
      l = FD_LAYOUT_APPEND( l, FD_SPAD_ALIGN,              FD_SPAD_FOOTPRINT( 1UL<<28UL )                       );
    }
  }

  return FD_LAYOUT_FINI(  l, scratch_align() );
}

static void
metrics_write( fd_execrp_tile_t * ctx ) {
  FD_MCNT_SET      ( EXECRP, SIGNATURE_VERIFIED,    ctx->metrics.sigverify_cnt );
  FD_MCNT_SET      ( EXECRP, POH_HASHED,     ctx->metrics.poh_hash_cnt  );
  FD_MCNT_ENUM_COPY( EXECRP, TXN_RESULT,   ctx->metrics.txn_result    );

  fd_progcache_metrics_t * pm = ctx->progcache->metrics;
  FD_MCNT_SET( EXECRP, PROGCACHE_LOOKUP,                 pm->lookup_cnt     );
  FD_MCNT_SET( EXECRP, PROGCACHE_HIT,                    pm->hit_cnt        );
  FD_MCNT_SET( EXECRP, PROGCACHE_MISS,                   pm->miss_cnt       );
  FD_MCNT_SET( EXECRP, PROGCACHE_OOM_HEAP,               pm->oom_heap_cnt   );
  FD_MCNT_SET( EXECRP, PROGCACHE_OOM_DESC,               pm->oom_desc_cnt   );
  FD_MCNT_SET( EXECRP, PROGCACHE_FILL,                   pm->fill_cnt       );
  FD_MCNT_SET( EXECRP, PROGCACHE_FILL_BYTES,             pm->fill_tot_sz    );
  FD_MCNT_SET( EXECRP, PROGCACHE_SPILL,                  pm->spill_cnt      );
  FD_MCNT_SET( EXECRP, PROGCACHE_SPILL_BYTES,            pm->spill_tot_sz   );
  FD_MCNT_SET( EXECRP, PROGCACHE_EVICTION,               pm->evict_cnt      );
  FD_MCNT_SET( EXECRP, PROGCACHE_EVICTION_BYTES,         pm->evict_tot_sz   );
  FD_MCNT_SET( EXECRP, PROGCACHE_DURATION_SECONDS,       pm->cum_pull_ticks );
  FD_MCNT_SET( EXECRP, PROGCACHE_LOAD_DURATION_SECONDS,  pm->cum_load_ticks );

  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_SETUP,  ctx->metrics.txn_load_cum_ticks+ctx->metrics.txn_check_cum_ticks );
  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_EXEC,   ctx->metrics.txn_exec_cum_ticks    );
  FD_MCNT_SET( EXECRP, TXN_REGIME_DURATION_NANOS_COMMIT, ctx->metrics.txn_commit_cum_ticks  );

  fd_runtime_t const * runtime = ctx->runtime;
  ulong cpi_ticks  = runtime->metrics.cpi_setup_cum_ticks +
                     runtime->metrics.cpi_commit_cum_ticks;
  ulong exec_ticks = fd_ulong_sat_sub( runtime->metrics.vm_exec_cum_ticks, cpi_ticks );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_SETUP,       runtime->metrics.vm_setup_cum_ticks   );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_COMMIT,      runtime->metrics.vm_commit_cum_ticks  );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_SETUP_CPI,   runtime->metrics.cpi_setup_cum_ticks  );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_COMMIT_CPI,  runtime->metrics.cpi_commit_cum_ticks );
  FD_MCNT_SET( EXECRP, VM_REGIME_DURATION_NANOS_INTERPRETER, exec_ticks                            );

  FD_MCNT_SET( EXECRP, CU_EXECUTED, runtime->metrics.cu_cum );

  FD_ACCDB_METRICS_WRITE( EXECRP, fd_accdb_metrics( ctx->accdb ) );
}


static void
publish_txn_finalized_msg( fd_execrp_tile_t *  ctx,
                           fd_stem_context_t * stem ) {
  fd_execrp_task_done_msg_t * msg  = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
  msg->bank_idx                  = ctx->bank->idx;
  msg->txn_exec->txn_idx         = ctx->txn_idx;
  msg->txn_exec->is_committable  = ctx->txn_out.err.is_committable;
  msg->txn_exec->is_fees_only    = ctx->txn_out.err.is_fees_only;
  msg->txn_exec->txn_err         = ctx->txn_out.err.txn_err;
  msg->txn_exec->slot            = ctx->slot;
  msg->txn_exec->bank_seq        = ctx->bank->bank_seq;
  msg->txn_exec->start_shred_idx = ctx->txn_in.txn->start_shred_idx;
  msg->txn_exec->end_shred_idx   = ctx->txn_in.txn->end_shred_idx;

  int is_vote = 0;
  if( FD_LIKELY( ctx->txn_out.details.is_simple_vote ) ) {
    fd_txn_t const * txn = TXN( ctx->txn_in.txn );
    uchar const *    payload = ctx->txn_in.txn->payload;
    fd_compact_tower_sync_serde_t tower_sync[ 1 ];
    if( FD_LIKELY( fd_txn_parse_simple_vote( txn, payload, tower_sync ) ) ) {
      fd_acct_addr_t const * accs = fd_txn_get_acct_addrs( txn, payload );
      *msg->txn_exec->vote.identity  = *(fd_pubkey_t const *)fd_type_pun_const( &accs[ 0 ] );
      *msg->txn_exec->vote.vote_acct = *(fd_pubkey_t const *)fd_type_pun_const( &accs[ txn->signature_cnt==1 ? 1 : 2 ] );

      ulong cur       = fd_ulong_if( tower_sync->root==ULONG_MAX, 0UL, tower_sync->root );
      ulong cnt       = 0UL;
      int   overflow  = 0;
      for( ulong i=0UL; i<tower_sync->lockouts_cnt; i++ ) {
        if( FD_UNLIKELY( __builtin_uaddl_overflow( cur, tower_sync->lockouts[ i ].offset, &cur ) ) ) { overflow = 1; break; }
        msg->txn_exec->vote.vote_slots[ cnt++ ] = cur;
      }
      if( FD_LIKELY( !overflow ) ) {
        msg->txn_exec->vote.vote_slot_cnt = (uchar)cnt;
        msg->txn_exec->vote.slot          = cnt ? msg->txn_exec->vote.vote_slots[ cnt-1UL ] : cur;
        is_vote                           = 1;
      }
    }
  }

  if( FD_UNLIKELY( !is_vote ) ) {
    msg->txn_exec->vote.slot          = ULONG_MAX;
    msg->txn_exec->vote.vote_slot_cnt = (uchar)0;
    *msg->txn_exec->vote.identity     = (fd_pubkey_t){ 0 };
    *msg->txn_exec->vote.vote_acct    = (fd_pubkey_t){ 0 };
  }

  if( FD_UNLIKELY( !msg->txn_exec->is_committable ) ) {
    uchar * signature = (uchar *)ctx->txn_in.txn->payload + TXN( ctx->txn_in.txn )->signature_off;
    FD_BASE58_ENCODE_64_BYTES( signature, signature_b58 );
    FD_LOG_WARNING(( "block marked dead (slot=%lu) because of invalid transaction (signature=%s) (txn_err=%d)", ctx->slot, signature_b58, ctx->txn_out.err.txn_err ));
  }

  fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_TXN_EXEC<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*msg), 0UL, ctx->dispatch_time_comp, fd_frag_meta_ts_comp( fd_tickcount() ) );

  ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
}

static inline void
after_credit( fd_execrp_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem; (void)opt_poll_in; (void)charge_busy;
  fd_startup_gate_idle( ctx->startup_gate );
}

static inline int
returnable_frag( fd_execrp_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  fd_startup_gate_busy( ctx->startup_gate );

  if( (sig&0xFFFFFFFFUL)!=ctx->tile_idx ) return 0;

  FD_MGAUGE_SET( EXECRP, PROCESSING, 1UL );

  if( FD_LIKELY( in_idx==ctx->replay_in->idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in->chunk0 || chunk > ctx->replay_in->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in->chunk0, ctx->replay_in->wmark ));
    }
    switch( sig>>32 ) {
      case FD_EXECRP_TT_TXN_EXEC: {
        /* Execute. */
        fd_execrp_txn_exec_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        ctx->bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
        FD_TEST( ctx->bank );
        ctx->txn_in.txn = msg->txn;
        memcpy( ctx->txn_in.fec_merkle_root, msg->fec_merkle_root, 32UL );
        ctx->txn_in.index_in_slot = msg->index_in_slot;

        /* Set the capture txn index from the message so account updates
           during commit are recorded with the correct transaction index. */
        if( FD_UNLIKELY( ctx->capture_ctx ) ) {
          ctx->capture_ctx->current_txn_idx = msg->capture_txn_idx;
        }

        fd_runtime_prepare_and_execute_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out );

        ctx->metrics.txn_result[ fd_execle_err_from_runtime_err( ctx->txn_out.err.txn_err ) ]++;

        if( FD_LIKELY( ctx->txn_out.err.is_committable ) ) {
          fd_runtime_commit_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out, ctx->report_transaction_diffs );
        } else {
          fd_runtime_cancel_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out, ctx->report_transaction_diffs );
        }

        long const txn_end_ticks = fd_tickcount();

        /* Notify replay. */
        ctx->txn_idx = msg->txn_idx;
        ctx->dispatch_time_comp = tspub;
        ctx->slot = ctx->bank->f.slot;
        publish_txn_finalized_msg( ctx, stem );

        /* Update metrics */
        ulong load_start_ticks_dt  = fd_ulong_if( ctx->txn_out.details.check_start_ticks==LONG_MAX  || ctx->txn_out.details.load_start_ticks==LONG_MAX,   0UL, (ulong)( ctx->txn_out.details.check_start_ticks  - ctx->txn_out.details.load_start_ticks ) );
        ulong check_start_ticks_dt = fd_ulong_if( ctx->txn_out.details.exec_start_ticks==LONG_MAX   || ctx->txn_out.details.check_start_ticks==LONG_MAX,  0UL, (ulong)( ctx->txn_out.details.exec_start_ticks   - ctx->txn_out.details.check_start_ticks ) );
        ulong exec_start_ticks_dt  = fd_ulong_if( ctx->txn_out.details.commit_start_ticks==LONG_MAX || ctx->txn_out.details.exec_start_ticks==LONG_MAX,   0UL, (ulong)( ctx->txn_out.details.commit_start_ticks - ctx->txn_out.details.exec_start_ticks ) );
        ulong commit_ticks_dt      = fd_ulong_if( txn_end_ticks==LONG_MAX                           || ctx->txn_out.details.commit_start_ticks==LONG_MAX, 0UL, (ulong)( txn_end_ticks                           - ctx->txn_out.details.commit_start_ticks ) );

        ctx->metrics.txn_load_cum_ticks   += load_start_ticks_dt;
        ctx->metrics.txn_check_cum_ticks  += check_start_ticks_dt;
        ctx->metrics.txn_exec_cum_ticks   += exec_start_ticks_dt;
        ctx->metrics.txn_commit_cum_ticks += commit_ticks_dt;

        break;
      }
      case FD_EXECRP_TT_TXN_SIGVERIFY: {
        fd_execrp_txn_sigverify_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        int res = fd_executor_txn_verify( msg->txn, ctx->sha_lj );
        fd_execrp_task_done_msg_t * out_msg = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
        out_msg->bank_idx               = msg->bank_idx;
        out_msg->txn_sigverify->txn_idx = msg->txn_idx;
        out_msg->txn_sigverify->err     = (res!=FD_RUNTIME_EXECUTE_SUCCESS);
        fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_TXN_SIGVERIFY<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*out_msg), 0UL, 0UL, 0UL );
        ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*out_msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
        ctx->metrics.sigverify_cnt += TXN( msg->txn )->signature_cnt;
        break;
      }
      case FD_EXECRP_TT_POH_HASH: {
        fd_execrp_poh_hash_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        fd_execrp_task_done_msg_t * out_msg = fd_chunk_to_laddr( ctx->execrp_replay_out->mem, ctx->execrp_replay_out->chunk );
        out_msg->bank_idx           = msg->bank_idx;
        out_msg->poh_hash->mblk_idx = msg->mblk_idx;
        out_msg->poh_hash->hashcnt  = msg->hashcnt;
        fd_sha256_hash_32_repeated( msg->hash, out_msg->poh_hash->hash, msg->hashcnt );
        fd_stem_publish( stem, ctx->execrp_replay_out->idx, (FD_EXECRP_TT_POH_HASH<<32)|ctx->tile_idx, ctx->execrp_replay_out->chunk, sizeof(*out_msg), 0UL, 0UL, 0UL );
        ctx->execrp_replay_out->chunk = fd_dcache_compact_next( ctx->execrp_replay_out->chunk, sizeof(*out_msg), ctx->execrp_replay_out->chunk0, ctx->execrp_replay_out->wmark );
        ctx->metrics.poh_hash_cnt += msg->hashcnt;
        break;
      }
      default: FD_LOG_CRIT(( "unexpected signature %lu", sig ));
    }
  } else FD_LOG_CRIT(( "invalid in_idx %lu", in_idx ));

  FD_MGAUGE_SET( EXECRP, PROCESSING, 0UL );

  return 0;
}

extern FD_TL int fd_wksp_oom_silent;

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_execrp_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_execrp_tile_t),    sizeof(fd_execrp_tile_t)                             );
  void * _txncache          = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),          fd_txncache_footprint( tile->execrp.max_live_slots ) );
  void * _accdb             = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),             fd_accdb_footprint( tile->execrp.max_live_slots )    );
  uchar * pc_scratch        = FD_SCRATCH_ALLOC_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN,   FD_PROGCACHE_SCRATCH_FOOTPRINT                       );

  void * _capture_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    _capture_ctx            = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),       fd_capture_ctx_footprint()                           );
  }

  void * _dump_proto_ctx = NULL;
  void * _txn_dump_ctx = NULL;
  void * _dumping = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    _dump_proto_ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dump_proto_ctx_t), sizeof(fd_dump_proto_ctx_t)                          );
    _txn_dump_ctx           = FD_SCRATCH_ALLOC_APPEND( l, fd_txn_dump_context_align(),  fd_txn_dump_context_footprint()                      );
    if( FD_UNLIKELY( tile->execrp.dump_instr_to_pb || tile->execrp.dump_syscall_to_pb || tile->execrp.dump_txn_to_pb ) ) {
      _dumping              = FD_SCRATCH_ALLOC_APPEND( l, FD_SPAD_ALIGN,                FD_SPAD_FOOTPRINT( 1UL<<28UL )                       );
    }
  }

  for( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( ctx->sha_mem+i ) );
    FD_TEST( sha );
    ctx->sha_lj[ i ] = sha;
  }

  ctx->txn_in.bundle.is_bundle = 0;
  ctx->tile_idx = tile->kind_id;

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  FD_TEST( banks_obj_id!=ULONG_MAX );

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  FD_TEST( fd_progcache_join( ctx->progcache, fd_topo_obj_laddr( topo, tile->execrp.progcache_obj_id ), pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->execrp.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->execrp.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );
  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );


  /* First find and setup the in-link from replay to exec. */
  ctx->replay_in->idx = fd_topo_find_tile_in_link( topo, tile, "replay_execrp", 0UL );
  FD_TEST( ctx->replay_in->idx!=ULONG_MAX );
  fd_topo_link_t const * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in->idx ] ];
  ctx->replay_in->mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in->chunk0 = fd_dcache_compact_chunk0( ctx->replay_in->mem, replay_in_link->dcache );
  ctx->replay_in->wmark  = fd_dcache_compact_wmark( ctx->replay_in->mem, replay_in_link->dcache, replay_in_link->mtu );
  ctx->replay_in->chunk  = ctx->replay_in->chunk0;

  ctx->execrp_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "execrp_replay", ctx->tile_idx );
  if( FD_LIKELY( ctx->execrp_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * execrp_replay_link = &topo->links[ tile->out_link_id[ ctx->execrp_replay_out->idx ] ];
    ctx->execrp_replay_out->mem    = topo->workspaces[ topo->objs[ execrp_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->execrp_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->execrp_replay_out->mem, execrp_replay_link->dcache );
    ctx->execrp_replay_out->wmark  = fd_dcache_compact_wmark( ctx->execrp_replay_out->mem, execrp_replay_link->dcache, execrp_replay_link->mtu );
    ctx->execrp_replay_out->chunk  = ctx->execrp_replay_out->chunk0;
  }


  ctx->capture_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.solcap_capture ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
    ctx->capture_ctx->solcap_start_slot = tile->execrp.capture_start_slot;

    ulong tile_idx = tile->kind_id;
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "cap_execrp", tile_idx );
    FD_TEST( idx!=ULONG_MAX );

    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ idx ] ];
    fd_capture_link_buf_t * cap_execrp_out = ctx->cap_execrp_out;
    cap_execrp_out->base.vt = &fd_capture_link_buf_vt;
    cap_execrp_out->idx     = idx;
    cap_execrp_out->mem     = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    cap_execrp_out->chunk0  = fd_dcache_compact_chunk0( cap_execrp_out->mem, link->dcache );
    cap_execrp_out->wmark   = fd_dcache_compact_wmark( cap_execrp_out->mem, link->dcache, link->mtu );
    cap_execrp_out->chunk   = cap_execrp_out->chunk0;
    cap_execrp_out->mcache  = link->mcache;
    cap_execrp_out->depth   = fd_mcache_depth( link->mcache );
    cap_execrp_out->seq     = 0UL;

    ulong consumer_tile_idx = fd_topo_find_tile(topo, "solcap", 0UL);
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ consumer_tile_idx ];
    cap_execrp_out->fseq = NULL;
    for( ulong j = 0UL; j < consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]  == link->id ) ) {
        cap_execrp_out->fseq = fd_fseq_join( fd_topo_obj_laddr( topo, consumer_tile->in_link_fseq_obj_id[ j ] ) );
        FD_TEST( cap_execrp_out->fseq );
        break;
      }
    }

    ctx->capture_ctx->capture_solcap  = 1;
    ctx->capture_ctx->capctx_type.buf = cap_execrp_out;
    ctx->capture_ctx->capture_link    = &cap_execrp_out->base;
  }

  ctx->dump_proto_ctx = NULL;
  if( FD_UNLIKELY( strlen( tile->execrp.dump_proto_dir ) ) ) {
    ctx->dump_proto_ctx = _dump_proto_ctx;

    /* General dumping config */
    ctx->dump_proto_ctx->dump_proto_output_dir = tile->execrp.dump_proto_dir;
    ctx->dump_proto_ctx->dump_proto_start_slot = tile->execrp.capture_start_slot;

    /* Syscall dumping config */
    ctx->dump_proto_ctx->dump_syscall_to_pb       = !!tile->execrp.dump_syscall_to_pb;
    ctx->dump_proto_ctx->dump_syscall_name_filter = tile->execrp.dump_syscall_name_filter;

    /* Instruction dumping config */
    ctx->dump_proto_ctx->dump_instr_to_pb                 = !!tile->execrp.dump_instr_to_pb;
    ctx->dump_proto_ctx->has_dump_instr_program_id_filter = !!strlen(tile->execrp.dump_instr_program_id_filter);
    if( FD_UNLIKELY( ctx->dump_proto_ctx->has_dump_instr_program_id_filter &&
                     !fd_base58_decode_32( tile->execrp.dump_instr_program_id_filter, ctx->dump_proto_ctx->dump_instr_program_id_filter ) ) ) {
      FD_LOG_ERR(( "failed to parse [capture.dump_instr_program_id_filter] %s", tile->execrp.dump_instr_program_id_filter ));
    }

    /* Transaction dumping config */
    ctx->dump_proto_ctx->dump_txn_to_pb      = !!tile->execrp.dump_txn_to_pb;
    ctx->dump_proto_ctx->dump_txn_as_fixture = !!tile->execrp.dump_txn_as_fixture;

    if( FD_UNLIKELY( ctx->dump_proto_ctx->dump_txn_as_fixture && !ctx->dump_proto_ctx->dump_txn_to_pb ) ) {
      FD_LOG_ERR(( "[capture.dump_txn_as_fixture] requires [capture.dump_txn_to_pb] to be enabled" ));
    }
  }

  /* Transaction dump context (for fixture dumping) */
  ctx->txn_dump_ctx = NULL;
  if( FD_UNLIKELY( ctx->dump_proto_ctx && ctx->dump_proto_ctx->dump_txn_to_pb ) ) {
    ctx->txn_dump_ctx = fd_txn_dump_context_join( fd_txn_dump_context_new( _txn_dump_ctx ) );
  }

  ctx->runtime->accdb                    = ctx->accdb;
  ctx->runtime->progcache                = ctx->progcache;
  ctx->runtime->status_cache             = ctx->txncache;
  memset( &ctx->runtime->log, 0, sizeof(ctx->runtime->log) );
  ctx->runtime->log.log_collector        = &ctx->log_collector;
  ctx->runtime->log.dumping_mem          = _dumping;
  ctx->runtime->log.tracing_mem          = NULL;
  ctx->runtime->log.capture_ctx          = ctx->capture_ctx;
  ctx->runtime->log.dump_proto_ctx       = ctx->dump_proto_ctx;
  ctx->runtime->log.txn_dump_ctx         = ctx->txn_dump_ctx;
  ctx->runtime->fuzz.enabled             = 0;
  ctx->runtime->fuzz.reclaim_accounts    = 0;
  ctx->runtime->accounts.executable_cnt  = 0UL;
  ctx->runtime->accounts.account_cnt     = 0UL;

  memset( &ctx->metrics,          0, sizeof(ctx->metrics)          );
  memset( &ctx->runtime->metrics, 0, sizeof(ctx->runtime->metrics) );

  ctx->report_transaction_diffs = tile->execrp.report_transaction_diffs;

  fd_wksp_oom_silent = 1;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_startup_gate_init( ctx->startup_gate, topo, tile->in_cnt );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_execrp_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_execrp_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */

  return out_cnt;
}

#define STEM_BURST (1UL)

/* Right now, depth of the replay_exec link and depth of the execrp_replay
   links is 16K.  At 1M TPS, that's ~16ms to fill.  But we also want to
   be conservative here, so we use 1ms. */
#define STEM_LAZY  (1000000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_execrp_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_execrp_tile_t)

#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile ) {
  /* execrp emits accdb_partition_added, plus runtime_txn when diffs are on. */
  ulong sz = sizeof(fd_event_accdb_partition_added_t);
  if( tile->execrp.report_transaction_diffs && sizeof(fd_event_runtime_txn_t)>sz ) sz = sizeof(fd_event_runtime_txn_t);
  return sz;
}

fd_topo_run_tile_t fd_tile_execrp = {
  .name                     = "execrp",
  .max_event_sz             = max_event_sz,
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
