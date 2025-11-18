#include "../tiles.h"

#include "generated/fd_pack_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../discof/replay/fd_replay_tile.h" // layering violation
#include "../fd_txn_m.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyswitch.h"
#include "../keyguard/fd_keyguard.h"
#include "../metrics/fd_metrics.h"
#include "../pack/fd_pack.h"
#include "../pack/fd_pack_cost.h"
#include "../pack/fd_pack_pacing.h"

#include <linux/unistd.h>
#include <string.h>

/* fd_pack is responsible for taking verified transactions, and
   arranging them into "microblocks" (groups) of transactions to
   be executed serially.  It can try to do clever things so that
   multiple microblocks can execute in parallel, if they don't
   write to the same accounts. */

#define IN_KIND_RESOLV       (0UL)
#define IN_KIND_POH          (1UL)
#define IN_KIND_BANK         (2UL)
#define IN_KIND_SIGN         (3UL)
#define IN_KIND_REPLAY       (4UL)
#define IN_KIND_EXECUTED_TXN (5UL)

/* Pace microblocks, but only slightly.  This helps keep performance
   more stable.  This limit is 2,000 microblocks/second/bank.  At 31
   transactions/microblock, that's 62k txn/sec/bank. */
#define MICROBLOCK_DURATION_NS  (0L)

/* There are 151 accepted blockhashes, but those don't include skips.
   This check is neither precise nor accurate, but just good enough.
   The bank tile does the final check.  We give a little margin for a
   few percent skip rate. */
#define TRANSACTION_LIFETIME_SLOTS 160UL

/* Time is normally a long, but pack expects a ulong.  Add -LONG_MIN to
   the time values so that LONG_MIN maps to 0, LONG_MAX maps to
   ULONG_MAX, and everything in between maps linearly with a slope of 1.
   Just subtracting LONG_MIN results in signed integer overflow, which
   is U.B. */
#define TIME_OFFSET 0x8000000000000000UL
FD_STATIC_ASSERT( (ulong)LONG_MIN+TIME_OFFSET==0UL,       time_offset );
FD_STATIC_ASSERT( (ulong)LONG_MAX+TIME_OFFSET==ULONG_MAX, time_offset );

/* 1.6 M cost units, enough for 1 max size transaction */
const ulong CUS_PER_MICROBLOCK = 1600000UL;

#define SMALL_MICROBLOCKS 1

#if SMALL_MICROBLOCKS
const float VOTE_FRACTION = 1.0f; /* schedule all available votes first */
#define EFFECTIVE_TXN_PER_MICROBLOCK 1UL
#else
const float VOTE_FRACTION = 0.75f; /* TODO: Is this the right value? */
#define EFFECTIVE_TXN_PER_MICROBLOCK MAX_TXN_PER_MICROBLOCK
#endif

/* There's overhead associated with each microblock the bank tile tries
   to execute it, so the optimal strategy is not to produce a microblock
   with a single transaction as soon as we receive it.  Basically, if we
   have less than 31 transactions, we want to wait a little to see if we
   receive additional transactions before we schedule a microblock.  We
   can model the optimum amount of time to wait, but the equation is
   complicated enough that we want to compute it before compile time.
   wait_duration[i] for i in [0, 31] gives the time in nanoseconds pack
   should wait after receiving its most recent transaction before
   scheduling if it has i transactions available.  Unsurprisingly,
   wait_duration[31] is 0.  wait_duration[0] is ULONG_MAX, so we'll
   always wait if we have 0 transactions. */
FD_IMPORT( wait_duration, "src/disco/pack/pack_delay.bin", ulong, 6, "" );



#if FD_PACK_USE_EXTRA_STORAGE
/* When we are done being leader for a slot and we are leader in the
   very next slot, it can still take some time to transition.  This is
   because the bank has to be finalized, a hash calculated, and various
   other things done in the replay stage to create the new child bank.

   During that time, pack cannot send transactions to banks so it needs
   to be able to buffer.  Typically, these so called "leader
   transitions" are short (<15 millis), so a low value here would
   suffice.  However, in some cases when there is memory pressure on the
   NUMA node or when the operating system context switches relevant
   threads out, it can take significantly longer.

   To prevent drops in these cases and because we assume banks are fast
   enough to drain this buffer once we do become leader, we set this
   buffer size to be quite large. */

#define DEQUE_NAME extra_txn_deq
#define DEQUE_T    fd_txn_e_t
#define DEQUE_MAX  (128UL*1024UL)
#include "../../../../util/tmpl/fd_deque.c"

#endif

/* Sync with src/app/shared/fd_config.c */
#define FD_PACK_STRATEGY_PERF     0
#define FD_PACK_STRATEGY_BALANCED 1
#define FD_PACK_STRATEGY_BUNDLE   2

static char const * const schedule_strategy_strings[3] = { "PRF", "BAL", "BUN" };


typedef struct {
  fd_acct_addr_t commission_pubkey[1];
  ulong          commission;
} block_builder_info_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_pack_in_ctx_t;

typedef struct {
  fd_pack_t *  pack;
  fd_txn_e_t * cur_spot;
  int          is_bundle; /* is the current transaction a bundle */

  uchar executed_txn_sig[ 64UL ];

  /* One of the FD_PACK_STRATEGY_* values defined above */
  int      strategy;

  /* The value passed to fd_pack_new, etc. */
  ulong    max_pending_transactions;

  /* The leader slot we are currently packing for, or ULONG_MAX if we
     are not the leader. */
  ulong  leader_slot;
  void const * leader_bank;
  ulong        leader_bank_idx;

  fd_became_leader_t _became_leader[1];

  /* The number of microblocks we have packed for the current leader
     slot.  Will always be <= slot_max_microblocks.  We must track
     this so that when we are done we can tell the PoH tile how many
     microblocks to expect in the slot. */
  ulong slot_microblock_cnt;

  /* Counter which increments when we've finished packing for a slot */
  uint pack_idx;

  ulong pack_txn_cnt; /* total num transactions packed since startup */

  /* The maximum number of microblocks that can be packed in this slot.
     Provided by the PoH tile when we become leader.*/
  ulong slot_max_microblocks;

  /* Cap (in bytes) of the amount of transaction data we produce in each
     block to avoid hitting the shred limits.  See where this is set for
     more explanation. */
  ulong slot_max_data;
  int   larger_shred_limits_per_block;

  /* Consensus critical slot cost limits. */
  struct {
    ulong slot_max_cost;
    ulong slot_max_vote_cost;
    ulong slot_max_write_cost_per_acct;
  } limits;

  /* If drain_banks is non-zero, then the pack tile must wait until all
     banks are idle before scheduling any more microblocks.  This is
     primarily helpful in irregular leader transitions, e.g. while being
     leader for slot N, we switch forks to a slot M (!=N+1) in which we
     are also leader.  We don't want to execute microblocks for
     different slots concurrently. */
  int drain_banks;

  /* Updated during housekeeping and used only for checking if the
     leader slot has ended.  Might be off by one housekeeping duration,
     but that should be small relative to a slot duration. */
  long  approx_wallclock_ns;

  /* approx_tickcount is updated in during_housekeeping() with
     fd_tickcount() and will match approx_wallclock_ns.  This is done
     because we need to include an accurate nanosecond timestamp in
     every fd_txn_p_t but don't want to have to call the expensive
     fd_log_wallclock() in in the critical path. We can use
     fd_tempo_tick_per_ns() to convert from ticks to nanoseconds over
     small periods of time. */
  long  approx_tickcount;

  fd_rng_t * rng;

  /* The end wallclock time of the leader slot we are currently packing
     for, if we are currently packing for a slot.*/
  long slot_end_ns;

  /* pacer and ticks_per_ns are used for pacing CUs through the slot,
     i.e. deciding when to schedule a microblock given the number of CUs
     that have been consumed so far.  pacer is an opaque pacing object,
     which is initialized when the pack tile is packing a slot.
     ticks_per_ns is the cached value from tempo. */
  fd_pack_pacing_t pacer[1];
  double           ticks_per_ns;

  /* last_successful_insert stores the tickcount of the last
     successful transaction insert. */
  long last_successful_insert;

  /* highest_observed_slot stores the highest slot number we've seen
     from any transaction coming from the resolv tile.  When this
     increases, we expire old transactions. */
  ulong highest_observed_slot;

  /* microblock_duration_ns, and wait_duration
     respectively scaled to be in ticks instead of nanoseconds */
  ulong microblock_duration_ticks;
  ulong wait_duration_ticks[ MAX_TXN_PER_MICROBLOCK+1UL ];

#if FD_PACK_USE_EXTRA_STORAGE
  /* In addition to the available transactions that pack knows about, we
     also store a larger ring buffer for handling cases when pack is
     full.  This is an fd_deque. */
  fd_txn_e_t * extra_txn_deq;
  int          insert_to_extra; /* whether the last insert was into pack or the extra deq */
#endif

  fd_pack_in_ctx_t in[ 32 ];
  int              in_kind[ 32 ];

  ulong    bank_cnt;
  ulong    bank_idle_bitset; /* bit i is 1 if we've observed *bank_current[i]==bank_expect[i] */
  int      poll_cursor; /* in [0, bank_cnt), the next bank to poll */
  int      use_consumed_cus;
  long     skip_cnt;
  ulong *  bank_current[ FD_PACK_MAX_BANK_TILES ];
  ulong    bank_expect[ FD_PACK_MAX_BANK_TILES  ];
  /* bank_ready_at[x] means don't check bank x until tickcount is at
     least bank_ready_at[x]. */
  long     bank_ready_at[ FD_PACK_MAX_BANK_TILES  ];

  fd_wksp_t * bank_out_mem;
  ulong       bank_out_chunk0;
  ulong       bank_out_wmark;
  ulong       bank_out_chunk;

  fd_wksp_t * poh_out_mem;
  ulong       poh_out_chunk0;
  ulong       poh_out_wmark;
  ulong       poh_out_chunk;

  ulong      insert_result[ FD_PACK_INSERT_RETVAL_CNT ];
  fd_histf_t schedule_duration[ 1 ];
  fd_histf_t no_sched_duration[ 1 ];
  fd_histf_t insert_duration  [ 1 ];
  fd_histf_t complete_duration[ 1 ];

  struct {
    uint metric_state;
    long metric_state_begin;
    long metric_timing[ 16 ];
  };

  struct {
    long time;
    ulong all[ FD_METRICS_TOTAL_SZ ];
  } last_sched_metrics[1];

    struct {
    long time;
    ulong all[ FD_METRICS_TOTAL_SZ ];
  } start_block_sched_metrics[1];

  struct {
    ulong id;
    ulong txn_cnt;
    ulong txn_received;
    ulong min_blockhash_slot;
    fd_txn_e_t * _txn[ FD_PACK_MAX_TXN_PER_BUNDLE ];
    fd_txn_e_t * const * bundle; /* points to _txn when non-NULL */
  } current_bundle[1];

  block_builder_info_t blk_engine_cfg[1];

  struct {
    int                   enabled;
    int                   ib_inserted; /* in this slot */
    fd_acct_addr_t        vote_pubkey[1];
    fd_acct_addr_t        identity_pubkey[1];
    fd_bundle_crank_gen_t gen[1];
    fd_acct_addr_t        tip_receiver_owner[1];
    ulong                 epoch;
    fd_bundle_crank_tip_payment_config_t prev_config[1]; /* as of start of slot, then updated */
    uchar                 recent_blockhash[32];
    fd_ed25519_sig_t      last_sig[1];

    fd_keyswitch_t *      keyswitch;
    fd_keyguard_client_t  keyguard_client[1];

    ulong                 metrics[4];
  } crank[1];


  /* Used between during_frag and after_frag */
  ulong pending_rebate_sz;
  union{ fd_pack_rebate_t rebate[1]; uchar footprint[USHORT_MAX]; } rebate[1];
} fd_pack_ctx_t;

#define BUNDLE_META_SZ 40UL
FD_STATIC_ASSERT( sizeof(block_builder_info_t)==BUNDLE_META_SZ, blk_engine_cfg );

#define FD_PACK_METRIC_STATE_TRANSACTIONS 0
#define FD_PACK_METRIC_STATE_BANKS        1
#define FD_PACK_METRIC_STATE_LEADER       2
#define FD_PACK_METRIC_STATE_MICROBLOCKS  3

/* Updates one component of the metric state.  If the state has changed,
   records the change. */
static inline void
update_metric_state( fd_pack_ctx_t * ctx,
                     long            effective_as_of,
                     int             type,
                     int             status ) {
  uint current_state = fd_uint_insert_bit( ctx->metric_state, type, status );
  if( FD_UNLIKELY( current_state!=ctx->metric_state ) ) {
    ctx->metric_timing[ ctx->metric_state ] += effective_as_of - ctx->metric_state_begin;
    ctx->metric_state_begin = effective_as_of;
    ctx->metric_state = current_state;
  }
}

static inline void
remove_ib( fd_pack_ctx_t * ctx ) {
  /* It's likely the initializer bundle is long scheduled, but we want to
     try deleting it just in case. */
  if( FD_UNLIKELY( ctx->crank->enabled & ctx->crank->ib_inserted ) ) {
    ulong deleted = fd_pack_delete_transaction( ctx->pack, (fd_ed25519_sig_t const *)ctx->crank->last_sig );
    FD_MCNT_INC( PACK, TRANSACTION_DELETED, deleted );
  }
  ctx->crank->ib_inserted = 0;
}


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_pack_limits_t limits[1] = {{
    .max_cost_per_block        = tile->pack.larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND,
    .max_vote_cost_per_block   = FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND,
    .max_write_cost_per_acct   = FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND,
    .max_data_bytes_per_block  = tile->pack.larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = EFFECTIVE_TXN_PER_MICROBLOCK,
    .max_microblocks_per_block = (ulong)UINT_MAX, /* Limit not known yet */
  }};

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t )                                   );
  l = FD_LAYOUT_APPEND( l, fd_rng_align(),           fd_rng_footprint()                                        );
  l = FD_LAYOUT_APPEND( l, fd_pack_align(),          fd_pack_footprint( tile->pack.max_pending_transactions,
                                                                        BUNDLE_META_SZ,
                                                                        tile->pack.bank_tile_count,
                                                                        limits                               ) );
#if FD_PACK_USE_EXTRA_STORAGE
  l = FD_LAYOUT_APPEND( l, extra_txn_deq_align(),    extra_txn_deq_footprint()                                 );
#endif
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
log_end_block_metrics( fd_pack_ctx_t * ctx,
                       long            now,
                       char const    * reason ) {
#define DELTA( m ) (fd_metrics_tl[ MIDX(COUNTER, PACK, TRANSACTION_SCHEDULE_##m) ] - ctx->last_sched_metrics->all[ MIDX(COUNTER, PACK, TRANSACTION_SCHEDULE_##m) ])
#define AVAIL( m ) (fd_metrics_tl[ MIDX(GAUGE, PACK, AVAILABLE_TRANSACTIONS_##m) ])
    FD_LOG_INFO(( "pack_end_block(slot=%lu,%s,%lx,ticks_since_last_schedule=%ld,reasons=%lu,%lu,%lu,%lu,%lu,%lu,%lu;remaining=%lu+%lu+%lu+%lu;smallest=%lu;cus=%lu->%lu)",
          ctx->leader_slot, reason, ctx->bank_idle_bitset, now-ctx->last_sched_metrics->time,
          DELTA( TAKEN ), DELTA( CU_LIMIT ), DELTA( FAST_PATH ), DELTA( BYTE_LIMIT ), DELTA( WRITE_COST ), DELTA( SLOW_PATH ), DELTA( DEFER_SKIP ),
          AVAIL(REGULAR), AVAIL(VOTES), AVAIL(BUNDLES), AVAIL(CONFLICTING),
          (fd_metrics_tl[ MIDX(GAUGE, PACK, SMALLEST_PENDING_TRANSACTION) ]),
          (ctx->last_sched_metrics->all[ MIDX(GAUGE, PACK, CUS_CONSUMED_IN_BLOCK) ]),
          (fd_metrics_tl               [ MIDX(GAUGE, PACK, CUS_CONSUMED_IN_BLOCK) ])
    ));
#undef AVAIL
#undef DELTA
}

static inline void
get_done_packing( fd_pack_ctx_t * ctx, fd_done_packing_t * done_packing ) {
    done_packing->microblocks_in_slot = ctx->slot_microblock_cnt;
    fd_pack_get_block_limits( ctx->pack, done_packing->limits_usage, done_packing->limits );

#define DELTA( mem, m ) (fd_metrics_tl[ MIDX(COUNTER, PACK, TRANSACTION_SCHEDULE_##m) ] - ctx->mem->all[ MIDX(COUNTER, PACK, TRANSACTION_SCHEDULE_##m) ])
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_TAKEN_IDX      ] = DELTA( start_block_sched_metrics, TAKEN      );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_CU_LIMIT_IDX   ] = DELTA( start_block_sched_metrics, CU_LIMIT   );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_FAST_PATH_IDX  ] = DELTA( start_block_sched_metrics, FAST_PATH  );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_BYTE_LIMIT_IDX ] = DELTA( start_block_sched_metrics, BYTE_LIMIT );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_WRITE_COST_IDX ] = DELTA( start_block_sched_metrics, WRITE_COST );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_SLOW_PATH_IDX  ] = DELTA( start_block_sched_metrics, SLOW_PATH  );
    done_packing->block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_DEFER_SKIP_IDX ] = DELTA( start_block_sched_metrics, DEFER_SKIP );

    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_TAKEN_IDX      ] = DELTA( last_sched_metrics, TAKEN      );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_CU_LIMIT_IDX   ] = DELTA( last_sched_metrics, CU_LIMIT   );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_FAST_PATH_IDX  ] = DELTA( last_sched_metrics, FAST_PATH  );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_BYTE_LIMIT_IDX ] = DELTA( last_sched_metrics, BYTE_LIMIT );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_WRITE_COST_IDX ] = DELTA( last_sched_metrics, WRITE_COST );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_SLOW_PATH_IDX  ] = DELTA( last_sched_metrics, SLOW_PATH  );
    done_packing->end_block_results[ FD_METRICS_ENUM_PACK_TXN_SCHEDULE_V_DEFER_SKIP_IDX ] = DELTA( last_sched_metrics, DEFER_SKIP );
#undef DELTA

  fd_pack_get_pending_smallest( ctx->pack, done_packing->pending_smallest, done_packing->pending_votes_smallest );
}

static inline void
metrics_write( fd_pack_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( PACK, TRANSACTION_INSERTED,          ctx->insert_result  );
  FD_MCNT_ENUM_COPY( PACK, METRIC_TIMING,        ((ulong*)ctx->metric_timing) );
  FD_MCNT_ENUM_COPY( PACK, BUNDLE_CRANK_STATUS,           ctx->crank->metrics );
  FD_MHIST_COPY( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS, ctx->schedule_duration );
  FD_MHIST_COPY( PACK, NO_SCHED_MICROBLOCK_DURATION_SECONDS, ctx->no_sched_duration );
  FD_MHIST_COPY( PACK, INSERT_TRANSACTION_DURATION_SECONDS,  ctx->insert_duration   );
  FD_MHIST_COPY( PACK, COMPLETE_MICROBLOCK_DURATION_SECONDS, ctx->complete_duration );

  fd_pack_metrics_write( ctx->pack );
}

static inline void
during_housekeeping( fd_pack_ctx_t * ctx ) {
  ctx->approx_wallclock_ns = fd_log_wallclock();
  ctx->approx_tickcount = fd_tickcount();

  if( FD_UNLIKELY( ctx->crank->enabled && fd_keyswitch_state_query( ctx->crank->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->crank->identity_pubkey, ctx->crank->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->crank->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
before_credit( fd_pack_ctx_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  if( FD_UNLIKELY( (ctx->cur_spot!=NULL) & !ctx->is_bundle ) ) {
    *charge_busy = 1;

    /* If we were overrun while processing a frag from an in, then
       cur_spot is left dangling and not cleaned up, so clean it up here
       (by returning the slot to the pool of free slots).  If the last
       transaction was a bundle, then we don't want to return it.  When
       we try to process the first transaction in the next bundle, we'll
       see we never got the full bundle and cancel the whole last
       bundle, returning all the storage to the pool. */
#if FD_PACK_USE_EXTRA_STORAGE
    if( FD_LIKELY( !ctx->insert_to_extra ) ) fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_spot );
    else                                     extra_txn_deq_remove_tail( ctx->extra_txn_deq       );
#else
    fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_spot );
#endif
    ctx->cur_spot = NULL;
  }
}

#if FD_PACK_USE_EXTRA_STORAGE
/* insert_from_extra: helper method to pop the transaction at the head
   off the extra txn deque and insert it into pack.  Requires that
   ctx->extra_txn_deq is non-empty, but it's okay to call it if pack is
   full.  Returns the result of fd_pack_insert_txn_fini. */
static inline int
insert_from_extra( fd_pack_ctx_t * ctx ) {
  fd_txn_e_t       * spot       = fd_pack_insert_txn_init( ctx->pack );
  fd_txn_e_t const * insert     = extra_txn_deq_peek_head( ctx->extra_txn_deq );
  fd_txn_t   const * insert_txn = TXN(insert->txnp);
  fd_memcpy( spot->txnp->payload, insert->txnp->payload, insert->txnp->payload_sz                                                     );
  fd_memcpy( TXN(spot->txnp),     insert_txn,            fd_txn_footprint( insert_txn->instr_cnt, insert_txn->addr_table_lookup_cnt ) );
  fd_memcpy( spot->alt_accts,     insert->alt_accts,     insert_txn->addr_table_adtl_cnt*sizeof(fd_acct_addr_t)                       );
  spot->txnp->payload_sz = insert->txnp->payload_sz;
  spot->txnp->source_tpu  = insert->txnp->source_tpu;
  spot->txnp->source_ipv4 = insert->txnp->source_ipv4;
  spot->txnp->scheduler_arrival_time_nanos = insert->txnp->scheduler_arrival_time_nanos;
  extra_txn_deq_remove_head( ctx->extra_txn_deq );

  ulong blockhash_slot = insert->txnp->blockhash_slot;

  ulong deleted;
  long insert_duration = -fd_tickcount();
  int result = fd_pack_insert_txn_fini( ctx->pack, spot, blockhash_slot, &deleted );
  insert_duration      += fd_tickcount();

  FD_MCNT_INC( PACK, TRANSACTION_DELETED, deleted );
  ctx->insert_result[ result + FD_PACK_INSERT_RETVAL_OFF ]++;
  fd_histf_sample( ctx->insert_duration, (ulong)insert_duration );
  FD_MCNT_INC( PACK, TRANSACTION_INSERTED_FROM_EXTRA, 1UL );
  return result;
}
#endif

static inline void
after_credit( fd_pack_ctx_t *     ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( (ctx->skip_cnt--)>0L ) ) return; /* It would take ages for this to hit LONG_MIN */

  long now = fd_tickcount();

  int pacing_bank_cnt = (int)fd_pack_pacing_enabled_bank_cnt( ctx->pacer, now );

  ulong bank_cnt = ctx->bank_cnt;


  /* If any banks are busy, check one of the busy ones see if it is
     still busy. */
  if( FD_LIKELY( ctx->bank_idle_bitset!=fd_ulong_mask_lsb( (int)bank_cnt ) ) ) {
    int   poll_cursor = ctx->poll_cursor;
    ulong busy_bitset = (~ctx->bank_idle_bitset) & fd_ulong_mask_lsb( (int)bank_cnt );

    /* Suppose bank_cnt is 4 and idle_bitset looks something like this
       (pretending it's a uchar):
                0000 1001
                       ^ busy cursor is 1
       Then busy_bitset is
                0000 0110
       Rotate it right by 2 bits
                1000 0001
       Find lsb returns 0, so busy cursor remains 2, and we poll bank 2.

       If instead idle_bitset were
                0000 1110
                       ^
       The rotated version would be
                0100 0000
       Find lsb will return 6, so busy cursor would be set to 0, and
       we'd poll bank 0, which is the right one. */
    poll_cursor++;
    poll_cursor = (poll_cursor + fd_ulong_find_lsb( fd_ulong_rotate_right( busy_bitset, (poll_cursor&63) ) )) & 63;

    if( FD_UNLIKELY(
        /* if microblock duration is 0, bypass the bank_ready_at check
           to avoid a potential cache miss.  Can't use an ifdef here
           because FD_UNLIKELY is a macro, but the compiler should
           eliminate the check easily. */
        ( (MICROBLOCK_DURATION_NS==0L) || (ctx->bank_ready_at[poll_cursor]<now) ) &&
        (fd_fseq_query( ctx->bank_current[poll_cursor] )==ctx->bank_expect[poll_cursor]) ) ) {
      *charge_busy = 1;
      ctx->bank_idle_bitset |= 1UL<<poll_cursor;

      long complete_duration = -fd_tickcount();
      int completed = fd_pack_microblock_complete( ctx->pack, (ulong)poll_cursor );
      complete_duration      += fd_tickcount();
      if( FD_LIKELY( completed ) ) fd_histf_sample( ctx->complete_duration, (ulong)complete_duration );
    }

    ctx->poll_cursor = poll_cursor;
  }


  /* If we time out on our slot, then stop being leader.  This can only
     happen in the first after_credit after a housekeeping. */
  if( FD_UNLIKELY( ctx->approx_wallclock_ns>=ctx->slot_end_ns && ctx->leader_slot!=ULONG_MAX ) ) {
    *charge_busy = 1;

    fd_done_packing_t * done_packing = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
    get_done_packing( ctx, done_packing );

    fd_stem_publish( stem, 1UL, fd_disco_bank_sig( ctx->leader_slot, ctx->pack_idx ), ctx->poh_out_chunk, sizeof(fd_done_packing_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, sizeof(fd_done_packing_t), ctx->poh_out_chunk0, ctx->poh_out_wmark );
    ctx->pack_idx++;

    log_end_block_metrics( ctx, now, "time" );
    ctx->drain_banks         = 1;
    ctx->leader_slot         = ULONG_MAX;
    ctx->slot_microblock_cnt = 0UL;
    fd_pack_end_block( ctx->pack );
    remove_ib( ctx );

    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_LEADER,       0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,        0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS,  0 );
    return;
  }

  /* Am I leader? If not, see about inserting at most one transaction
     from extra storage.  It's important not to insert too many
     transactions here, or we won't end up servicing dedup_pack enough.
     If extra storage is empty or pack is full, do nothing. */
  if( FD_UNLIKELY( ctx->leader_slot==ULONG_MAX ) ) {
#if FD_PACK_USE_EXTRA_STORAGE
    if( FD_UNLIKELY( !extra_txn_deq_empty( ctx->extra_txn_deq ) &&
         fd_pack_avail_txn_cnt( ctx->pack )<ctx->max_pending_transactions ) ) {
      *charge_busy = 1;

      int result = insert_from_extra( ctx );
      if( FD_LIKELY( result>=0 ) ) ctx->last_successful_insert = now;
    }
#endif
    return;
  }

  /* Am I in drain mode?  If so, check if I can exit it */
  if( FD_UNLIKELY( ctx->drain_banks ) ) {
    if( FD_LIKELY( ctx->bank_idle_bitset==fd_ulong_mask_lsb( (int)bank_cnt ) ) ) {
      ctx->drain_banks = 0;

      /* Pack notifies poh when banks are drained so that poh can
         relinquish pack's ownership over the slot bank (by decrementing
         its Arc). We do this by sending a ULONG_MAX sig over the
         pack_poh mcache.

         TODO: This is only needed for Frankendancer, not Firedancer,
         which manages bank lifetime different. */
      fd_stem_publish( stem, 1UL, ULONG_MAX, 0UL, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else {
      return;
    }
  }

  /* Have I sent the max allowed microblocks? Nothing to do. */
  if( FD_UNLIKELY( ctx->slot_microblock_cnt>=ctx->slot_max_microblocks ) ) return;

  /* Do I have enough transactions and/or have I waited enough time? */
  if( FD_UNLIKELY( (ulong)(now-ctx->last_successful_insert) <
        ctx->wait_duration_ticks[ fd_ulong_min( fd_pack_avail_txn_cnt( ctx->pack ), MAX_TXN_PER_MICROBLOCK ) ] ) ) {
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, 0 );
    return;
  }

  int any_ready     = 0;
  int any_scheduled = 0;

  *charge_busy = 1;

  if( FD_LIKELY( ctx->crank->enabled ) ) {
    block_builder_info_t const * top_meta = fd_pack_peek_bundle_meta( ctx->pack );
    if( FD_UNLIKELY( top_meta ) ) {
      /* Have bundles, in a reasonable state to crank. */

      fd_txn_e_t * _bundle[ 1UL ];
      fd_txn_e_t * const * bundle = fd_pack_insert_bundle_init( ctx->pack, _bundle, 1UL );

      ulong txn_sz = fd_bundle_crank_generate( ctx->crank->gen, ctx->crank->prev_config, top_meta->commission_pubkey,
          ctx->crank->identity_pubkey, ctx->crank->tip_receiver_owner, ctx->crank->epoch, top_meta->commission,
          bundle[0]->txnp->payload, TXN( bundle[0]->txnp ) );

      if( FD_LIKELY( txn_sz==0UL ) ) { /* Everything in good shape! */
        fd_pack_insert_bundle_cancel( ctx->pack, bundle, 1UL );
        fd_pack_set_initializer_bundles_ready( ctx->pack );
        ctx->crank->metrics[ 0 ]++; /* BUNDLE_CRANK_STATUS_NOT_NEEDED */
      }
      else if( FD_LIKELY( txn_sz<ULONG_MAX ) ) {
        bundle[0]->txnp->payload_sz  = (ushort)txn_sz;
        bundle[0]->txnp->source_tpu  = FD_TXN_M_TPU_SOURCE_BUNDLE;
        bundle[0]->txnp->source_ipv4 = 0; /* not applicable */
        bundle[0]->txnp->scheduler_arrival_time_nanos = ctx->approx_wallclock_ns + (long)((double)(fd_tickcount() - ctx->approx_tickcount) / ctx->ticks_per_ns);
        memcpy( bundle[0]->txnp->payload+TXN(bundle[0]->txnp)->recent_blockhash_off, ctx->crank->recent_blockhash, 32UL );

        fd_keyguard_client_sign( ctx->crank->keyguard_client, bundle[0]->txnp->payload+1UL,
            bundle[0]->txnp->payload+65UL, txn_sz-65UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );

        memcpy( ctx->crank->last_sig, bundle[0]->txnp->payload+1UL, 64UL );

        ctx->crank->ib_inserted = 1;
        ulong deleted;
        int retval = fd_pack_insert_bundle_fini( ctx->pack, bundle, 1UL, ctx->leader_slot-1UL, 1, NULL, &deleted );
        FD_MCNT_INC( PACK, TRANSACTION_DELETED, deleted );
        ctx->insert_result[ retval + FD_PACK_INSERT_RETVAL_OFF ]++;
        if( FD_UNLIKELY( retval<0 ) ) {
          ctx->crank->metrics[ 3 ]++; /* BUNDLE_CRANK_STATUS_INSERTION_FAILED */
          FD_LOG_WARNING(( "inserting initializer bundle returned %i", retval ));
        } else {
          /* Update the cached copy of the on-chain state.  This seems a
             little dangerous, since we're updating it as if the bundle
             succeeded without knowing if that's true, but here's why
             it's safe:

             From now until we get the rebate call for this initializer
             bundle (which lets us know if it succeeded or failed), pack
             will be in [Pending] state, which means peek_bundle_meta
             will return NULL, so we won't read this state.

             Then, if the initializer bundle failed, we'll go into
             [Failed] IB state until the end of the block, which will
             cause top_meta to remain NULL so we don't read these values
             again.

             Otherwise, the initializer bundle succeeded, which means
             that these are the right values to use. */
          fd_bundle_crank_apply( ctx->crank->gen, ctx->crank->prev_config, top_meta->commission_pubkey,
                                 ctx->crank->tip_receiver_owner, ctx->crank->epoch, top_meta->commission );
          ctx->crank->metrics[ 1 ]++; /* BUNDLE_CRANK_STATUS_INSERTED */
        }
      } else {
        /* Already logged a warning in this case */
        fd_pack_insert_bundle_cancel( ctx->pack, bundle, 1UL );
        ctx->crank->metrics[ 2 ]++; /* BUNDLE_CRANK_STATUS_CREATION_FAILED' */
      }
    }
  }

  /* Try to schedule the next microblock. */
  if( FD_LIKELY( ctx->bank_idle_bitset ) ) { /* Optimize for schedule */
    any_ready = 1;

    int i = fd_ulong_find_lsb( ctx->bank_idle_bitset );

    int flags;

    switch( ctx->strategy ) {
      default:
      case FD_PACK_STRATEGY_PERF:
        flags = FD_PACK_SCHEDULE_VOTE | FD_PACK_SCHEDULE_BUNDLE | FD_PACK_SCHEDULE_TXN;
        break;
      case FD_PACK_STRATEGY_BALANCED:
        /* We want to exempt votes from pacing, so we always allow
           scheduling votes.  It doesn't really make much sense to pace
           bundles, because they get scheduled in FIFO order.  However,
           we keep pacing for normal transactions.  For example, if
           pacing_bank_cnt is 0, then pack won't schedule normal
           transactions to any bank tile. */
        flags = FD_PACK_SCHEDULE_VOTE | fd_int_if( i==0,              FD_PACK_SCHEDULE_BUNDLE, 0 )
                                      | fd_int_if( i<pacing_bank_cnt, FD_PACK_SCHEDULE_TXN,    0 );
        break;
      case FD_PACK_STRATEGY_BUNDLE:
        flags = FD_PACK_SCHEDULE_VOTE | FD_PACK_SCHEDULE_BUNDLE
                                      | fd_int_if( ctx->slot_end_ns - ctx->approx_wallclock_ns<50000000L, FD_PACK_SCHEDULE_TXN,  0 );
        break;
    }

    fd_txn_p_t * microblock_dst = fd_chunk_to_laddr( ctx->bank_out_mem, ctx->bank_out_chunk );
    long schedule_duration = -fd_tickcount();
    ulong schedule_cnt = fd_pack_schedule_next_microblock( ctx->pack, CUS_PER_MICROBLOCK, VOTE_FRACTION, (ulong)i, flags, microblock_dst );
    schedule_duration      += fd_tickcount();
    fd_histf_sample( (schedule_cnt>0UL) ? ctx->schedule_duration : ctx->no_sched_duration, (ulong)schedule_duration );

    if( FD_LIKELY( schedule_cnt ) ) {
      any_scheduled = 1;
      long  now2   = fd_tickcount();
      ulong tsorig = (ulong)fd_frag_meta_ts_comp( now  ); /* A bound on when we observed bank was idle */
      ulong tspub  = (ulong)fd_frag_meta_ts_comp( now2 );
      ulong chunk  = ctx->bank_out_chunk;
      ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);
      fd_microblock_bank_trailer_t * trailer = (fd_microblock_bank_trailer_t*)(microblock_dst+schedule_cnt);
      trailer->bank = ctx->leader_bank;
      trailer->bank_idx = ctx->leader_bank_idx;
      trailer->microblock_idx = ctx->slot_microblock_cnt;
      trailer->pack_idx = ctx->pack_idx;
      trailer->pack_txn_idx = ctx->pack_txn_cnt;
      trailer->is_bundle = !!(microblock_dst->flags & FD_TXN_P_FLAGS_BUNDLE);

      ulong sig = fd_disco_poh_sig( ctx->leader_slot, POH_PKT_TYPE_MICROBLOCK, (ulong)i );
      fd_stem_publish( stem, 0UL, sig, chunk, msg_sz+sizeof(fd_microblock_bank_trailer_t), 0UL, tsorig, tspub );
      ctx->bank_expect[ i ] = stem->seqs[0]-1UL;
      ctx->bank_ready_at[i] = now2 + (long)ctx->microblock_duration_ticks;
      ctx->bank_out_chunk = fd_dcache_compact_next( ctx->bank_out_chunk, msg_sz+sizeof(fd_microblock_bank_trailer_t), ctx->bank_out_chunk0, ctx->bank_out_wmark );
      ctx->slot_microblock_cnt += fd_ulong_if( trailer->is_bundle, schedule_cnt, 1UL );
      ctx->pack_idx += fd_uint_if( trailer->is_bundle, (uint)schedule_cnt, 1U );
      ctx->pack_txn_cnt += schedule_cnt;

      ctx->bank_idle_bitset = fd_ulong_pop_lsb( ctx->bank_idle_bitset );
      ctx->skip_cnt         = (long)schedule_cnt * fd_long_if( ctx->use_consumed_cus, (long)bank_cnt/2L, 1L );
      fd_pack_pacing_update_consumed_cus( ctx->pacer, fd_pack_current_block_cost( ctx->pack ), now2 );

      memcpy( ctx->last_sched_metrics->all, (ulong const *)fd_metrics_tl, sizeof(ctx->last_sched_metrics->all) );
      ctx->last_sched_metrics->time = now2;

      /* If we're using CU rebates, then we have one in for each bank in
        addition to the two normal ones. We want to skip schedule attempts
        for (bank_cnt + 1) link polls after a successful schedule attempt.
        */
      fd_long_store_if( ctx->use_consumed_cus, &(ctx->skip_cnt), (long)(ctx->bank_cnt + 1) );
    }
  }

  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,       any_ready     );
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS, any_scheduled );
  now = fd_tickcount();
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, fd_pack_avail_txn_cnt( ctx->pack )>0 );

#if FD_PACK_USE_EXTRA_STORAGE
  if( FD_UNLIKELY( !extra_txn_deq_empty( ctx->extra_txn_deq ) ) ) {
    /* Don't start pulling from the extra storage until the available
       transaction count drops below half. */
    ulong avail_space   = (ulong)fd_long_max( 0L, (long)(ctx->max_pending_transactions>>1)-(long)fd_pack_avail_txn_cnt( ctx->pack ) );
    ulong qty_to_insert = fd_ulong_min( 10UL, fd_ulong_min( extra_txn_deq_cnt( ctx->extra_txn_deq ), avail_space ) );
    int any_successes = 0;
    for( ulong i=0UL; i<qty_to_insert; i++ ) any_successes |= (0<=insert_from_extra( ctx ));
    if( FD_LIKELY( any_successes ) ) ctx->last_successful_insert = now;
  }
#endif

  /* Did we send the maximum allowed microblocks? Then end the slot. */
  if( FD_UNLIKELY( ctx->slot_microblock_cnt==ctx->slot_max_microblocks )) {
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_LEADER,       0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,        0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS,  0 );
    /* The pack object also does this accounting and increases this
       metric, but we end the slot early so won't see it unless we also
       increment it here. */
    FD_MCNT_INC( PACK, MICROBLOCK_PER_BLOCK_LIMIT, 1UL );
    log_end_block_metrics( ctx, now, "microblock" );

    fd_done_packing_t * done_packing = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
    get_done_packing( ctx, done_packing );

    fd_stem_publish( stem, 1UL, fd_disco_bank_sig( ctx->leader_slot, ctx->pack_idx ), ctx->poh_out_chunk, sizeof(fd_done_packing_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, sizeof(fd_done_packing_t), ctx->poh_out_chunk0, ctx->poh_out_wmark );
    ctx->pack_idx++;

    ctx->drain_banks         = 1;
    ctx->leader_slot         = ULONG_MAX;
    ctx->slot_microblock_cnt = 0UL;
    fd_pack_end_block( ctx->pack );
    remove_ib( ctx );

  }
}


/* At this point, we have started receiving frag seq with details in
    mline at time now.  Speculatively process it here. */

static inline void
during_frag( fd_pack_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq FD_PARAM_UNUSED,
             ulong           sig,
             ulong           chunk,
             ulong           sz,
             ulong           ctl FD_PARAM_UNUSED ) {

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY: {
    if( FD_LIKELY( sig!=REPLAY_SIG_BECAME_LEADER ) ) return;

    /* There was a leader transition.  Handle it. */
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=sizeof(fd_became_leader_t) ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    fd_memcpy( ctx->_became_leader, dcache_entry, sizeof(fd_became_leader_t) );
    return;
  }
  case IN_KIND_POH: {
      /* Not interested in stamped microblocks, only leader updates. */
    if( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_BECAME_LEADER ) return;

    /* There was a leader transition.  Handle it. */
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=sizeof(fd_became_leader_t) ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    fd_memcpy( ctx->_became_leader, dcache_entry, sizeof(fd_became_leader_t) );
    return;
  }
  case IN_KIND_BANK: {
    FD_TEST( ctx->use_consumed_cus );
      /* For a previous slot */
    if( FD_UNLIKELY( sig!=ctx->leader_slot ) ) return;

    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz<FD_PACK_REBATE_MIN_SZ
          || sz>FD_PACK_REBATE_MAX_SZ ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    ctx->pending_rebate_sz = sz;
    fd_memcpy( ctx->rebate, dcache_entry, sz );
    return;
  }
  case IN_KIND_RESOLV: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_TPU_RESOLVED_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    fd_txn_m_t * txnm = (fd_txn_m_t *)dcache_entry;
    ulong payload_sz  = txnm->payload_sz;
    ulong txn_t_sz    = txnm->txn_t_sz;
    uint  source_ipv4 = txnm->source_ipv4;
    uchar source_tpu  = txnm->source_tpu;
    FD_TEST( payload_sz<=FD_TPU_MTU    );
    FD_TEST( txn_t_sz  <=FD_TXN_MAX_SZ );
    fd_txn_t * txn  = fd_txn_m_txn_t( txnm );

    ulong addr_table_sz = 32UL*txn->addr_table_adtl_cnt;
    FD_TEST( addr_table_sz<=32UL*FD_TXN_ACCT_ADDR_MAX );

    if( FD_UNLIKELY( (ctx->leader_slot==ULONG_MAX) & (sig>ctx->highest_observed_slot) ) ) {
      /* Using the resolv tile's knowledge of the current slot is a bit
         of a hack, since we don't get any info if there are no
         transactions and we're not leader.  We're actually in exactly
         the case where that's okay though.  The point of calling
         expire_before long before we become leader is so that we don't
         drop new but low-fee-paying transactions when pack is clogged
         with expired but high-fee-paying transactions.  That can only
         happen if we are getting transactions. */
      ctx->highest_observed_slot = sig;
      ulong exp_cnt = fd_pack_expire_before( ctx->pack, fd_ulong_max( ctx->highest_observed_slot, TRANSACTION_LIFETIME_SLOTS )-TRANSACTION_LIFETIME_SLOTS );
      FD_MCNT_INC( PACK, TRANSACTION_EXPIRED, exp_cnt );
    }


    ulong bundle_id = txnm->block_engine.bundle_id;
    if( FD_UNLIKELY( bundle_id ) ) {
      ctx->is_bundle = 1;
      if( FD_LIKELY( bundle_id!=ctx->current_bundle->id ) ) {
        if( FD_UNLIKELY( ctx->current_bundle->bundle ) ) {
          FD_MCNT_INC( PACK, TRANSACTION_DROPPED_PARTIAL_BUNDLE, ctx->current_bundle->txn_received );
          fd_pack_insert_bundle_cancel( ctx->pack, ctx->current_bundle->bundle, ctx->current_bundle->txn_cnt );
        }
        ctx->current_bundle->id                 = bundle_id;
        ctx->current_bundle->txn_cnt            = txnm->block_engine.bundle_txn_cnt;
        ctx->current_bundle->min_blockhash_slot = ULONG_MAX;
        ctx->current_bundle->txn_received       = 0UL;

        if( FD_UNLIKELY( ctx->current_bundle->txn_cnt==0UL ) ) {
          FD_MCNT_INC( PACK, TRANSACTION_DROPPED_PARTIAL_BUNDLE, 1UL );
          ctx->current_bundle->id = 0UL;
          return;
        }
        ctx->blk_engine_cfg->commission = txnm->block_engine.commission;
        memcpy( ctx->blk_engine_cfg->commission_pubkey->b, txnm->block_engine.commission_pubkey, 32UL );

        ctx->current_bundle->bundle = fd_pack_insert_bundle_init( ctx->pack, ctx->current_bundle->_txn, ctx->current_bundle->txn_cnt );
      }
      ctx->cur_spot                           = ctx->current_bundle->bundle[ ctx->current_bundle->txn_received ];
      ctx->current_bundle->min_blockhash_slot = fd_ulong_min( ctx->current_bundle->min_blockhash_slot, sig );
    } else {
      ctx->is_bundle = 0;
#if FD_PACK_USE_EXTRA_STORAGE
      if( FD_LIKELY( ctx->leader_slot!=ULONG_MAX || fd_pack_avail_txn_cnt( ctx->pack )<ctx->max_pending_transactions ) ) {
        ctx->cur_spot = fd_pack_insert_txn_init( ctx->pack );
        ctx->insert_to_extra = 0;
      } else {
        if( FD_UNLIKELY( extra_txn_deq_full( ctx->extra_txn_deq ) ) ) {
          extra_txn_deq_remove_head( ctx->extra_txn_deq );
          FD_MCNT_INC( PACK, TRANSACTION_DROPPED_FROM_EXTRA, 1UL );
        }
        ctx->cur_spot = extra_txn_deq_peek_tail( extra_txn_deq_insert_tail( ctx->extra_txn_deq ) );
        /* We want to store the current time in cur_spot so that we can
           track its expiration better.  We just stash it in the CU
           fields, since those aren't important right now. */
        ctx->cur_spot->txnp->blockhash_slot = sig;
        ctx->insert_to_extra                = 1;
        FD_MCNT_INC( PACK, TRANSACTION_INSERTED_TO_EXTRA, 1UL );
      }
#else
      ctx->cur_spot = fd_pack_insert_txn_init( ctx->pack );
#endif
    }

    /* We get transactions from the resolv tile.
       The transactions should have been parsed and verified. */
    FD_MCNT_INC( PACK, NORMAL_TRANSACTION_RECEIVED, 1UL );

    fd_memcpy( ctx->cur_spot->txnp->payload, fd_txn_m_payload( txnm ), payload_sz    );
    fd_memcpy( TXN(ctx->cur_spot->txnp),     txn,                      txn_t_sz      );
    fd_memcpy( ctx->cur_spot->alt_accts,     fd_txn_m_alut( txnm ),    addr_table_sz );
    ctx->cur_spot->txnp->scheduler_arrival_time_nanos = ctx->approx_wallclock_ns + (long)((double)(fd_tickcount() - ctx->approx_tickcount) / ctx->ticks_per_ns);
    ctx->cur_spot->txnp->payload_sz  = payload_sz;
    ctx->cur_spot->txnp->source_ipv4 = source_ipv4;
    ctx->cur_spot->txnp->source_tpu  = source_tpu;

    break;
  }
  case IN_KIND_EXECUTED_TXN: {
    FD_TEST( sz==64UL || sz==160UL );
    fd_memcpy( ctx->executed_txn_sig, dcache_entry, 64 );
    break;
  }
  }
}


/* After the transaction has been fully received, and we know we were
   not overrun while reading it, insert it into pack. */

static inline void
after_frag( fd_pack_ctx_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  long now = fd_tickcount();

  ulong leader_slot = ULONG_MAX;
  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPLAY:
      if( FD_UNLIKELY( sig!=REPLAY_SIG_BECAME_LEADER ) ) return;
      leader_slot = ctx->_became_leader->slot;

      memcpy( ctx->start_block_sched_metrics->all, (ulong const *)fd_metrics_tl, sizeof(ctx->start_block_sched_metrics->all) );
      ctx->start_block_sched_metrics->time = now;
      break;
    case IN_KIND_POH:
      if( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_BECAME_LEADER ) return;
      leader_slot = fd_disco_poh_sig_slot( sig );
      break;
    default:
      break;
  }

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
  case IN_KIND_POH: {
    long now_ticks = fd_tickcount();
    long now_ns    = fd_log_wallclock();

    if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX ) ) {
      fd_done_packing_t * done_packing = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
      get_done_packing( ctx, done_packing );

      fd_stem_publish( stem, 1UL, fd_disco_bank_sig( ctx->leader_slot, ctx->pack_idx ), ctx->poh_out_chunk, sizeof(fd_done_packing_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, sizeof(fd_done_packing_t), ctx->poh_out_chunk0, ctx->poh_out_wmark );
      ctx->pack_idx++;

      FD_LOG_WARNING(( "switching to slot %lu while packing for slot %lu. Draining bank tiles.", leader_slot, ctx->leader_slot ));
      log_end_block_metrics( ctx, now_ticks, "switch" );
      ctx->drain_banks         = 1;
      ctx->leader_slot         = ULONG_MAX;
      ctx->slot_microblock_cnt = 0UL;
      fd_pack_end_block( ctx->pack );
      remove_ib( ctx );
    }
    ctx->leader_slot = leader_slot;

    ulong exp_cnt = fd_pack_expire_before( ctx->pack, fd_ulong_max( ctx->leader_slot, TRANSACTION_LIFETIME_SLOTS )-TRANSACTION_LIFETIME_SLOTS );
    FD_MCNT_INC( PACK, TRANSACTION_EXPIRED, exp_cnt );

    ctx->leader_bank          = ctx->_became_leader->bank;
    ctx->leader_bank_idx      = ctx->_became_leader->bank_idx;
    ctx->slot_max_microblocks = ctx->_became_leader->max_microblocks_in_slot;
    /* Reserve some space in the block for ticks */
    ctx->slot_max_data        = (ctx->larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK)
                                      - 48UL*(ctx->_became_leader->ticks_per_slot+ctx->_became_leader->total_skipped_ticks);

    ctx->limits.slot_max_cost                = ctx->_became_leader->limits.slot_max_cost;
    ctx->limits.slot_max_vote_cost           = ctx->_became_leader->limits.slot_max_vote_cost;
    ctx->limits.slot_max_write_cost_per_acct = ctx->_became_leader->limits.slot_max_write_cost_per_acct;

    /* ticks_per_ns is probably relatively stable over 400ms, but not
       over several hours, so we need to compute the slot duration in
       milliseconds first and then convert to ticks.  This doesn't need
       to be super accurate, but we don't want it to vary wildly. */
    long end_ticks = now_ticks + (long)((double)fd_long_max( ctx->_became_leader->slot_end_ns - now_ns, 1L )*ctx->ticks_per_ns);
    /* We may still get overrun, but then we'll never use this and just
       reinitialize it the next time when we actually become leader. */
    fd_pack_pacing_init( ctx->pacer, now_ticks, end_ticks, (float)ctx->ticks_per_ns, ctx->limits.slot_max_cost );

    if( FD_UNLIKELY( ctx->crank->enabled ) ) {
      /* If we get overrun, we'll just never use these values, but the
         old values aren't really useful either. */
      ctx->crank->epoch = ctx->_became_leader->epoch;
      *(ctx->crank->prev_config) = *(ctx->_became_leader->bundle->config);
      memcpy( ctx->crank->recent_blockhash,   ctx->_became_leader->bundle->last_blockhash,     32UL );
      memcpy( ctx->crank->tip_receiver_owner, ctx->_became_leader->bundle->tip_receiver_owner, 32UL );
    }

    FD_LOG_INFO(( "pack_became_leader(slot=%lu,ends_at=%ld)", ctx->leader_slot, ctx->_became_leader->slot_end_ns ));

    update_metric_state( ctx, fd_tickcount(), FD_PACK_METRIC_STATE_LEADER, 1 );

    ctx->slot_end_ns = ctx->_became_leader->slot_end_ns;
    fd_pack_limits_t limits[ 1 ];
    limits->max_cost_per_block = ctx->limits.slot_max_cost;
    limits->max_data_bytes_per_block = ctx->slot_max_data;
    limits->max_microblocks_per_block = ctx->slot_max_microblocks;
    limits->max_vote_cost_per_block = ctx->limits.slot_max_vote_cost;
    limits->max_write_cost_per_acct = ctx->limits.slot_max_write_cost_per_acct;
    limits->max_txn_per_microblock = ULONG_MAX; /* unused */
    fd_pack_set_block_limits( ctx->pack, limits );
    fd_pack_pacing_update_consumed_cus( ctx->pacer, fd_pack_current_block_cost( ctx->pack ), now );

    break;
  }
  case IN_KIND_BANK: {
    /* For a previous slot */
    if( FD_UNLIKELY( sig!=ctx->leader_slot ) ) return;

    fd_pack_rebate_cus( ctx->pack, ctx->rebate->rebate );
    ctx->pending_rebate_sz = 0UL;
    fd_pack_pacing_update_consumed_cus( ctx->pacer, fd_pack_current_block_cost( ctx->pack ), now );
    break;
  }
  case IN_KIND_RESOLV: {
    /* Normal transaction case */
#if FD_PACK_USE_EXTRA_STORAGE
    if( FD_LIKELY( !ctx->insert_to_extra ) ) {
#else
    if( 1 ) {
#endif
    if( FD_UNLIKELY( ctx->is_bundle ) ) {
      if( FD_UNLIKELY( ctx->current_bundle->txn_cnt==0UL ) ) return;
      if( FD_UNLIKELY( ++(ctx->current_bundle->txn_received)==ctx->current_bundle->txn_cnt ) ) {
        ulong deleted;
        long insert_duration = -fd_tickcount();
        int result = fd_pack_insert_bundle_fini( ctx->pack, ctx->current_bundle->bundle, ctx->current_bundle->txn_cnt, ctx->current_bundle->min_blockhash_slot, 0, ctx->blk_engine_cfg, &deleted );
        insert_duration      += fd_tickcount();
        FD_MCNT_INC( PACK, TRANSACTION_DELETED, deleted );
        ctx->insert_result[ result + FD_PACK_INSERT_RETVAL_OFF ] += ctx->current_bundle->txn_received;
        fd_histf_sample( ctx->insert_duration, (ulong)insert_duration );
        ctx->current_bundle->bundle = NULL;
      }
    } else {
      ulong blockhash_slot = sig;
      ulong deleted;
      long insert_duration = -fd_tickcount();
      int result = fd_pack_insert_txn_fini( ctx->pack, ctx->cur_spot, blockhash_slot, &deleted );
      insert_duration      += fd_tickcount();
      FD_MCNT_INC( PACK, TRANSACTION_DELETED, deleted );
      ctx->insert_result[ result + FD_PACK_INSERT_RETVAL_OFF ]++;
      fd_histf_sample( ctx->insert_duration, (ulong)insert_duration );
      if( FD_LIKELY( result>=0 ) ) ctx->last_successful_insert = now;
    }
    }

    ctx->cur_spot = NULL;
    break;
  }
  case IN_KIND_EXECUTED_TXN: {
    ulong deleted = fd_pack_delete_transaction( ctx->pack, fd_type_pun( ctx->executed_txn_sig ) );
    FD_MCNT_INC( PACK, TRANSACTION_ALREADY_EXECUTED, deleted );
    break;
  }
  }

  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, fd_pack_avail_txn_cnt( ctx->pack )>0 );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  if( FD_LIKELY( !tile->pack.bundle.enabled ) ) return;
  if( FD_UNLIKELY( !tile->pack.bundle.vote_account_path[0] ) ) {
    FD_LOG_WARNING(( "Disabling bundle crank because no vote account was specified" ));
    return;
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_pack_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->pack.bundle.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->pack.bundle.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->crank->identity_pubkey->b, identity_key, 32UL );

  if( FD_UNLIKELY( !fd_base58_decode_32( tile->pack.bundle.vote_account_path, ctx->crank->vote_pubkey->b ) ) ) {
    const uchar * vote_key = fd_keyload_load( tile->pack.bundle.vote_account_path, /* pubkey only: */ 1 );
    fd_memcpy( ctx->crank->vote_pubkey->b, vote_key, 32UL );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->pack.max_pending_transactions >= USHORT_MAX-10UL ) ) FD_LOG_ERR(( "pack tile supports up to %lu pending transactions", USHORT_MAX-11UL ));

  fd_pack_limits_t limits_upper[1] = {{
    .max_cost_per_block        = tile->pack.larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND,
    .max_vote_cost_per_block   = FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND,
    .max_write_cost_per_acct   = FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND,
    .max_data_bytes_per_block  = tile->pack.larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = EFFECTIVE_TXN_PER_MICROBLOCK,
    .max_microblocks_per_block = (ulong)UINT_MAX, /* Limit not known yet */
  }};

  ulong pack_footprint = fd_pack_footprint( tile->pack.max_pending_transactions, BUNDLE_META_SZ, tile->pack.bank_tile_count, limits_upper );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_pack_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  fd_rng_t *      rng = fd_rng_join( fd_rng_new( FD_SCRATCH_ALLOC_APPEND( l, fd_rng_align(), fd_rng_footprint() ), 0U, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_new failed" ));

  fd_pack_limits_t limits_lower[1] = {{
    .max_cost_per_block        = tile->pack.larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND,
    .max_vote_cost_per_block   = FD_PACK_MAX_VOTE_COST_PER_BLOCK_LOWER_BOUND,
    .max_write_cost_per_acct   = FD_PACK_MAX_WRITE_COST_PER_ACCT_LOWER_BOUND,
    .max_data_bytes_per_block  = tile->pack.larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = EFFECTIVE_TXN_PER_MICROBLOCK,
    .max_microblocks_per_block = (ulong)UINT_MAX, /* Limit not known yet */
  }};

  ctx->pack = fd_pack_join( fd_pack_new( FD_SCRATCH_ALLOC_APPEND( l, fd_pack_align(), pack_footprint ),
                                         tile->pack.max_pending_transactions, BUNDLE_META_SZ, tile->pack.bank_tile_count,
                                         limits_lower, rng ) );
  if( FD_UNLIKELY( !ctx->pack ) ) FD_LOG_ERR(( "fd_pack_new failed" ));

  if( FD_UNLIKELY( tile->in_cnt>32UL ) ) FD_LOG_ERR(( "Too many input links (%lu>32) to pack tile", tile->in_cnt ));

  FD_TEST( tile->in_cnt<sizeof( ctx->in_kind )/sizeof( ctx->in_kind[0] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_LIKELY(      !strcmp( link->name, "resolv_pack"  ) ) ) ctx->in_kind[ i ] = IN_KIND_RESOLV;
    else if( FD_LIKELY( !strcmp( link->name, "dedup_pack"   ) ) ) ctx->in_kind[ i ] = IN_KIND_RESOLV;
    else if( FD_LIKELY( !strcmp( link->name, "poh_pack"     ) ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else if( FD_LIKELY( !strcmp( link->name, "bank_pack"    ) ) ) ctx->in_kind[ i ] = IN_KIND_BANK;
    else if( FD_LIKELY( !strcmp( link->name, "sign_pack"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "executed_txn" ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECUTED_TXN;
    else if( FD_LIKELY( !strcmp( link->name, "exec_sig"     ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECUTED_TXN;
    else FD_LOG_ERR(( "pack tile has unexpected input link %lu %s", i, link->name ));
  }

  ulong bank_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ i ];
    if( FD_UNLIKELY( strcmp( consumer_tile->name, "bank" ) && strcmp( consumer_tile->name, "replay" ) ) ) continue;
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ 0 ] ) ) bank_cnt++;
    }
  }

  // if( FD_UNLIKELY( !bank_cnt                            ) ) FD_LOG_ERR(( "pack tile connects to no banking tiles" ));
  if( FD_UNLIKELY( bank_cnt>FD_PACK_MAX_BANK_TILES      ) ) FD_LOG_ERR(( "pack tile connects to too many banking tiles" ));
  // if( FD_UNLIKELY( bank_cnt!=tile->pack.bank_tile_count ) ) FD_LOG_ERR(( "pack tile connects to %lu banking tiles, but tile->pack.bank_tile_count is %lu", bank_cnt, tile->pack.bank_tile_count ));

  FD_TEST( (tile->pack.schedule_strategy>=0) & (tile->pack.schedule_strategy<=FD_PACK_STRATEGY_BUNDLE) );

  ctx->crank->enabled = tile->pack.bundle.enabled;
  if( FD_UNLIKELY( tile->pack.bundle.enabled ) ) {
    if( FD_UNLIKELY( !fd_bundle_crank_gen_init( ctx->crank->gen, (fd_acct_addr_t const *)tile->pack.bundle.tip_distribution_program_addr,
            (fd_acct_addr_t const *)tile->pack.bundle.tip_payment_program_addr,
            (fd_acct_addr_t const *)ctx->crank->vote_pubkey->b,
            (fd_acct_addr_t const *)tile->pack.bundle.tip_distribution_authority,
            schedule_strategy_strings[ tile->pack.schedule_strategy ],
            tile->pack.bundle.commission_bps ) ) ) {
      FD_LOG_ERR(( "constructing bundle generator failed" ));
    }

    ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_pack", tile->kind_id );
    ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "pack_sign", tile->kind_id );
    FD_TEST( sign_in_idx!=ULONG_MAX );
    fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
    fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
    if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->crank->keyguard_client,
            sign_out->mcache,
            sign_out->dcache,
            sign_in->mcache,
            sign_in->dcache,
            sign_out->mtu ) ) ) ) {
      FD_LOG_ERR(( "failed to construct keyguard" ));
    }
    /* Initialize enough of the prev config that it produces a
       transaction */
    ctx->crank->prev_config->discriminator       = 0x82ccfa1ee0aa0c9bUL;
    ctx->crank->prev_config->tip_receiver->b[1]  = 1;
    ctx->crank->prev_config->block_builder->b[2] = 1;

    memset( ctx->crank->tip_receiver_owner, '\0', 32UL );
    memset( ctx->crank->recent_blockhash,   '\0', 32UL );
    memset( ctx->crank->last_sig,           '\0', 64UL );
    ctx->crank->ib_inserted    = 0;
    ctx->crank->epoch          = 0UL;
    ctx->crank->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
    FD_TEST( ctx->crank->keyswitch );
  } else {
    memset( ctx->crank, '\0', sizeof(ctx->crank) );
  }


#if FD_PACK_USE_EXTRA_STORAGE
  ctx->extra_txn_deq = extra_txn_deq_join( extra_txn_deq_new( FD_SCRATCH_ALLOC_APPEND( l, extra_txn_deq_align(),
                                                                                          extra_txn_deq_footprint() ) ) );
#endif

  ctx->cur_spot                      = NULL;
  ctx->is_bundle                     = 0;
  ctx->strategy                      = tile->pack.schedule_strategy;
  ctx->max_pending_transactions      = tile->pack.max_pending_transactions;
  ctx->leader_slot                   = ULONG_MAX;
  ctx->leader_bank                   = NULL;
  ctx->leader_bank_idx               = ULONG_MAX;
  ctx->pack_idx                      = 0UL;
  ctx->slot_microblock_cnt           = 0UL;
  ctx->pack_txn_cnt                  = 0UL;
  ctx->slot_max_microblocks          = 0UL;
  ctx->slot_max_data                 = 0UL;
  ctx->larger_shred_limits_per_block = tile->pack.larger_shred_limits_per_block;
  ctx->drain_banks                   = 0;
  ctx->approx_wallclock_ns           = fd_log_wallclock();
  ctx->approx_tickcount              = fd_tickcount();
  ctx->rng                           = rng;
  ctx->ticks_per_ns                  = fd_tempo_tick_per_ns( NULL );
  ctx->last_successful_insert        = 0L;
  ctx->highest_observed_slot         = 0UL;
  ctx->microblock_duration_ticks     = (ulong)(fd_tempo_tick_per_ns( NULL )*(double)MICROBLOCK_DURATION_NS  + 0.5);
#if FD_PACK_USE_EXTRA_STORAGE
  ctx->insert_to_extra               = 0;
#endif
  ctx->use_consumed_cus              = tile->pack.use_consumed_cus;
  ctx->crank->enabled                = tile->pack.bundle.enabled;

  ctx->wait_duration_ticks[ 0 ] = ULONG_MAX;
  for( ulong i=1UL; i<MAX_TXN_PER_MICROBLOCK+1UL; i++ ) {
    ctx->wait_duration_ticks[ i ]=(ulong)(fd_tempo_tick_per_ns( NULL )*(double)wait_duration[ i ] + 0.5);
  }

  ctx->limits.slot_max_cost                = limits_lower->max_cost_per_block;
  ctx->limits.slot_max_vote_cost           = limits_lower->max_vote_cost_per_block;
  ctx->limits.slot_max_write_cost_per_acct = limits_lower->max_write_cost_per_acct;

  ctx->bank_cnt         = tile->pack.bank_tile_count;
  ctx->poll_cursor      = 0;
  ctx->skip_cnt         = 0L;
  ctx->bank_idle_bitset = fd_ulong_mask_lsb( (int)tile->pack.bank_tile_count );
  for( ulong i=0UL; i<tile->pack.bank_tile_count; i++ ) {
    ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", i );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ctx->bank_current[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    ctx->bank_expect[ i ] = ULONG_MAX;
    if( FD_UNLIKELY( !ctx->bank_current[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
    ctx->bank_ready_at[ i ] = 0L;
    FD_TEST( ULONG_MAX==fd_fseq_query( ctx->bank_current[ i ] ) );
  }

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->bank_out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->bank_out_chunk0 = fd_dcache_compact_chunk0( ctx->bank_out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->bank_out_wmark  = fd_dcache_compact_wmark ( ctx->bank_out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->bank_out_chunk  = ctx->bank_out_chunk0;

  ctx->poh_out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 1 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->poh_out_chunk0 = fd_dcache_compact_chunk0( ctx->poh_out_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache );
  ctx->poh_out_wmark  = fd_dcache_compact_wmark ( ctx->poh_out_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache, topo->links[ tile->out_link_id[ 1 ] ].mtu );
  ctx->poh_out_chunk  = ctx->poh_out_chunk0;

  /* Initialize metrics storage */
  memset( ctx->insert_result, '\0', FD_PACK_INSERT_RETVAL_CNT * sizeof(ulong) );
  fd_histf_join( fd_histf_new( ctx->schedule_duration, FD_MHIST_SECONDS_MIN( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS ),
                                                       FD_MHIST_SECONDS_MAX( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->no_sched_duration, FD_MHIST_SECONDS_MIN( PACK, NO_SCHED_MICROBLOCK_DURATION_SECONDS ),
                                                       FD_MHIST_SECONDS_MAX( PACK, NO_SCHED_MICROBLOCK_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->insert_duration,   FD_MHIST_SECONDS_MIN( PACK, INSERT_TRANSACTION_DURATION_SECONDS  ),
                                                       FD_MHIST_SECONDS_MAX( PACK, INSERT_TRANSACTION_DURATION_SECONDS  ) ) );
  fd_histf_join( fd_histf_new( ctx->complete_duration, FD_MHIST_SECONDS_MIN( PACK, COMPLETE_MICROBLOCK_DURATION_SECONDS ),
                                                       FD_MHIST_SECONDS_MAX( PACK, COMPLETE_MICROBLOCK_DURATION_SECONDS ) ) );
  ctx->metric_state = 0;
  ctx->metric_state_begin = fd_tickcount();
  memset( ctx->metric_timing,             '\0', 16*sizeof(long)                        );
  memset( ctx->current_bundle,            '\0', sizeof(ctx->current_bundle)            );
  memset( ctx->blk_engine_cfg,            '\0', sizeof(ctx->blk_engine_cfg)            );
  memset( ctx->last_sched_metrics,        '\0', sizeof(ctx->last_sched_metrics)        );
  memset( ctx->start_block_sched_metrics, '\0', sizeof(ctx->start_block_sched_metrics) );
  memset( ctx->crank->metrics,            '\0', sizeof(ctx->crank->metrics)            );

  FD_LOG_INFO(( "packing microblocks of at most %lu transactions to %lu bank tiles using strategy %i", EFFECTIVE_TXN_PER_MICROBLOCK, tile->pack.bank_tile_count, ctx->strategy ));

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_pack_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_pack_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

/* We want lazy (measured in ns) to be small enough that the producer
    and the consumer never have to wait for credits.  For most tango
    links, we use a default worst case speed coming from 100 Gbps
    Ethernet.  That's not very suitable for microblocks that go from
    pack to bank.  Instead we manually estimate the very aggressive
    1000ns per microblock, and then reduce it further (in line with the
    default lazy value computation) to ensure the random value chosen
    based on this won't lead to credit return stalls. */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_pack_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_pack_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_pack = {
  .name                     = "pack",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
