#include "tiles.h"

#include "generated/pack_seccomp.h"

#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../ballet/pack/fd_pack.h"

#include <linux/unistd.h>

/* fd_pack is responsible for taking verified transactions, and
   arranging them into "microblocks" (groups) of transactions to
   be executed serially.  It can try to do clever things so that
   multiple microblocks can execute in parallel, if they don't
   write to the same accounts. */

#define POH_IN_IDX (2UL)

#define MAX_SLOTS_PER_EPOCH          432000UL

/* For now, produce microblocks as fast as possible. */
#define MICROBLOCK_DURATION_NS  (0L)

#define TRANSACTION_LIFETIME_NS (60UL*1000UL*1000UL*1000UL) /* 60s */

/* About 6 kB on the stack */
#define FD_PACK_PACK_MAX_OUT FD_PACK_MAX_BANK_TILES

/* Time is normally a long, but pack expects a ulong.  Add -LONG_MIN to
   the time values so that LONG_MIN maps to 0, LONG_MAX maps to
   ULONG_MAX, and everything in between maps linearly with a slope of 1.
   Just subtracting LONG_MIN results in signed integer overflow, which
   is U.B. */
#define TIME_OFFSET 0x8000000000000000UL
FD_STATIC_ASSERT( (ulong)LONG_MIN+TIME_OFFSET==0UL,       time_offset );
FD_STATIC_ASSERT( (ulong)LONG_MAX+TIME_OFFSET==ULONG_MAX, time_offset );

/* Each block is limited to 32k parity shreds.  We don't want pack to
   produce a block with so many transactions we can't shred it, but the
   correspondance between transactions and parity shreds is somewhat
   complicated, so we need to use conservative limits.

   Except for the final batch in the block, the current version of the
   shred tile shreds microblock batches of size (25431, 63671] bytes,
   including the microblock headers, but excluding the microblock count.
   The worst case size by bytes/parity shred is a 25871 byte microblock
   batch, which produces 31 parity shreds.  The final microblock batch,
   however, may be as bad as 48 bytes triggering the creation of 17
   parity shreds.  This gives us a limit of floor((32k - 17)/31)*25871 +
   48 = 27,319,824 bytes.

   To get this right, the pack tile needs to add in the 48-byte
   microblock headers for each microblock, and we also need to subtract
   out the tick bytes, which aren't known until PoH initialization is
   complete.

   Note that the number of parity shreds in each FEC set is always at
   least as many as the number of data shreds, so we don't need to
   consider the data shreds limit. */
#define FD_PACK_MAX_DATA_PER_BLOCK (((32UL*1024UL-17UL)/31UL)*25871UL + 48UL)

/* Optionally allow up to 128k shreds per block for benchmarking. */
#define LARGER_MAX_DATA_PER_BLOCK  (((4UL*32UL*1024UL-17UL)/31UL)*25871UL + 48UL)


/* Optionally allow a larger limit for benchmarking */
#define LARGER_MAX_COST_PER_BLOCK (13UL*48000000UL)

/* 1.5 M cost units, enough for 1 max size transaction */
const ulong CUS_PER_MICROBLOCK = 1500000UL;

const float VOTE_FRACTION = 0.75;

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
FD_IMPORT( wait_duration, "src/ballet/pack/pack_delay.bin", ulong, 6, "" );

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_pack_in_ctx_t;

typedef struct {
  fd_pack_t *  pack;
  fd_txn_p_t * cur_spot;

  /* The leader slot we are currently packing for, or ULONG_MAX if we
     are not the leader. */
  ulong  leader_slot;
  void const * leader_bank;

  /* The number of microblocks we have packed for the current leader
     slot.  Will always be <= slot_max_microblocks.  We must track
     this so that when we are done we can tell the PoH tile how many
     microblocks to expect in the slot. */
  ulong slot_microblock_cnt;

  /* The maximum number of microblocks that can be packed in this slot.
     Provided by the PoH tile when we become leader.*/
  ulong slot_max_microblocks;

  /* Cap (in bytes) of the amount of transaction data we produce in each
     block to avoid hitting the shred limits.  See where this is set for
     more explanation. */
  ulong slot_max_data;
  int   larger_shred_limits_per_block;

  fd_rng_t * rng;

  /* The end wallclock time of the leader slot we are currently packing
     for, if we are currently packing for a slot.

     _slot_end_ns is used as a temporary between during_frag and
     after_frag in case the tile gets overrun. */
  long _slot_end_ns;
  long slot_end_ns;

  /* last_successful_insert stores the wall time in ns of the last
     succcessful transaction insert. */
  long last_successful_insert;

  fd_pack_in_ctx_t in[ 32 ];

  ulong    bank_cnt;
  ulong *  bank_current[ FD_PACK_PACK_MAX_OUT ];
  ulong    bank_expect[ FD_PACK_PACK_MAX_OUT  ];
  long     bank_ready_at[ FD_PACK_PACK_MAX_OUT  ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  ulong      insert_result[ FD_PACK_INSERT_RETVAL_CNT ];
  fd_histf_t schedule_duration[ 1 ];
  fd_histf_t insert_duration  [ 1 ];

  struct {
    uint metric_state;
    long metric_state_begin;
    long metric_timing[ 16 ];
  };
} fd_pack_ctx_t;


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


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_pack_limits_t limits[1] = {{
    .max_cost_per_block        = tile->pack.larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : FD_PACK_MAX_COST_PER_BLOCK,
    .max_vote_cost_per_block   = FD_PACK_MAX_VOTE_COST_PER_BLOCK,
    .max_write_cost_per_acct   = FD_PACK_MAX_WRITE_COST_PER_ACCT,
    .max_data_bytes_per_block  = tile->pack.larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = MAX_TXN_PER_MICROBLOCK,
    .max_microblocks_per_block = (ulong)UINT_MAX, /* Limit not known yet */
  }};

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_rng_align(),           fd_rng_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_pack_align(), fd_pack_footprint( tile->pack.max_pending_transactions,
                                                     tile->pack.bank_tile_count,
                                                     limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_pack_ctx_t ) );
}

static inline void
metrics_write( void * _ctx ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  FD_MCNT_ENUM_COPY( PACK, TRANSACTION_INSERTED,          ctx->insert_result  );
  FD_MCNT_ENUM_COPY( PACK, METRIC_TIMING,        ((ulong*)ctx->metric_timing) );
  FD_MHIST_COPY( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS, ctx->schedule_duration );
  FD_MHIST_COPY( PACK, INSERT_TRANSACTION_DURATION_SECONDS,  ctx->insert_duration   );
}

static inline void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  (void)mux;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( ctx->cur_spot ) ) {
    /* If we were overrun while processing a frag from an in, then cur_spot
       is left dangling and not cleaned up, so clean it up here (by returning
       the slot to the pool of free slots). */
    fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_spot );
    ctx->cur_spot = NULL;
  }
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  /* If we time out on our slot, then stop being leader. */
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>=ctx->slot_end_ns && ctx->leader_slot!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( ctx->slot_microblock_cnt<ctx->slot_max_microblocks )) {
      /* As an optimization, The PoH tile will automatically end a slot
         if it receives the maximum allowed microblocks, since it knows
         there is nothing left to receive.  In that case, we don't need
         to send a DONE_PACKING notification, since they are already on
         the next slot.  If we did send one it would just get dropped. */
      fd_done_packing_t * done_packing = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      done_packing->microblocks_in_slot = ctx->slot_microblock_cnt;

      fd_mux_publish( mux, fd_disco_poh_sig( ctx->leader_slot, POH_PKT_TYPE_DONE_PACKING, ULONG_MAX ), ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
      ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_done_packing_t), ctx->out_chunk0, ctx->out_wmark );
    }

    ctx->leader_slot = ULONG_MAX;
    fd_pack_end_block( ctx->pack );
    ctx->slot_microblock_cnt = 0UL;
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_LEADER,       0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,        0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS,  0 );
    return;
  }

  /* Am I leader? If not, nothing to do. */
  if( FD_UNLIKELY( ctx->leader_slot==ULONG_MAX ) ) return;

  /* Have I sent the max allowed microblocks? Nothing to do. */
  if( FD_UNLIKELY( ctx->slot_microblock_cnt>=ctx->slot_max_microblocks ) ) return;

  /* Do I have enough microblocks and/or have I waited enough time? */
  if( FD_UNLIKELY( (ulong)(now-ctx->last_successful_insert) <
        wait_duration[ fd_ulong_min( fd_pack_avail_txn_cnt( ctx->pack ), MAX_TXN_PER_MICROBLOCK ) ] ) ) {
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, 0 );
    return;
  }

  ulong bank_cnt = ctx->bank_cnt;

  /* Randomize the starting point for the loop so that bank tile 0
     doesn't always get the best transactions. */
  ulong offset = fd_rng_ulong_roll( ctx->rng, bank_cnt );

  int any_ready = 0;
  int any_scheduled = 0;
  /* Is it time to schedule the next microblock? For each banking
     thread, if it's not busy... */
  for( ulong _i=0UL; _i<bank_cnt; _i++ ) {
    ulong i = (_i + offset)%bank_cnt;

    /* optimize for the case we send a microblock */
    if( FD_LIKELY( (fd_fseq_query( ctx->bank_current[i] )==ctx->bank_expect[i]) & (ctx->bank_ready_at[i]<now) ) ) {
      any_ready = 1;

      fd_pack_microblock_complete( ctx->pack, i );
      /* TODO: record metrics for expire */
      fd_pack_expire_before( ctx->pack, fd_ulong_min( (ulong)now+TIME_OFFSET, TRANSACTION_LIFETIME_NS )-TRANSACTION_LIFETIME_NS );

      void * microblock_dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      long schedule_duration = -fd_tickcount();
      ulong schedule_cnt = fd_pack_schedule_next_microblock( ctx->pack, CUS_PER_MICROBLOCK, VOTE_FRACTION, i, microblock_dst );
      schedule_duration      += fd_tickcount();
      fd_histf_sample( ctx->schedule_duration, (ulong)schedule_duration );

      if( FD_LIKELY( schedule_cnt ) ) {
        any_scheduled = 1;
        ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        ulong chunk  = ctx->out_chunk;
        ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);
        fd_microblock_bank_trailer_t * trailer = (fd_microblock_bank_trailer_t*)((uchar*)microblock_dst+msg_sz);
        trailer->bank = ctx->leader_bank;

        ulong sig = fd_disco_poh_sig( ctx->leader_slot, POH_PKT_TYPE_MICROBLOCK, i );
        fd_mux_publish( mux, sig, chunk, msg_sz+sizeof(fd_microblock_bank_trailer_t), 0UL, 0UL, tspub );
        ctx->bank_expect[ i ] = *mux->seq-1UL;
        ctx->bank_ready_at[i] = now + MICROBLOCK_DURATION_NS;
        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, msg_sz+sizeof(fd_microblock_bank_trailer_t), ctx->out_chunk0, ctx->out_wmark );
        ctx->slot_microblock_cnt++;

        /* We have set burst to 1 below, so we might have no credits
           after publishing here.  We need to wait til the next credit
           loop check to publish another microblock. */
        break;
      }
    }
  }
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,       any_ready     );
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS, any_scheduled );
  now = fd_log_wallclock();
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, fd_pack_avail_txn_cnt( ctx->pack )>0 );

  /* Did we send the maximum allowed microblocks? Then end the slot. */
  if( FD_UNLIKELY( ctx->slot_microblock_cnt==ctx->slot_max_microblocks )) {
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_LEADER,       0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_BANKS,        0 );
    update_metric_state( ctx, now, FD_PACK_METRIC_STATE_MICROBLOCKS,  0 );
    ctx->leader_slot = ULONG_MAX;
    ctx->slot_microblock_cnt = 0UL;
    fd_pack_end_block( ctx->pack );
  }
}

/* At this point, we have started receiving frag seq with details in
    mline at time now.  Speculatively process it here. */

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

  if( FD_UNLIKELY( in_idx==POH_IN_IDX ) ) {
    if( fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_BECAME_LEADER ) {
      /* Not interested in stamped microblocks, only leader updates. */
      *opt_filter = 1;
      return;
    }

    /* There was a leader transition.  Handle it. */
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=sizeof(fd_became_leader_t) ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    FD_TEST( ctx->leader_slot==ULONG_MAX );
    ctx->leader_slot = fd_disco_poh_sig_slot( sig );

    fd_became_leader_t * became_leader = (fd_became_leader_t *)dcache_entry;
    ctx->leader_bank          = became_leader->bank;
    ctx->slot_max_microblocks = became_leader->max_microblocks_in_slot;
    /* Reserve some space in the block for ticks */
    ctx->slot_max_data        = (ctx->larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK)
                                      - 48UL*became_leader->ticks_per_slot;


    /* The dcache might get overrun, so set slot_end_ns to 0, so if it does
       the slot will get skipped.  Then update it in the `after_frag` case
       below to the correct value. */
    ctx->slot_end_ns = 0L;
    ctx->_slot_end_ns = became_leader->slot_end_ns;

    update_metric_state( ctx, fd_log_wallclock(), FD_PACK_METRIC_STATE_LEADER, 1 );
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  ctx->cur_spot              = fd_pack_insert_txn_init( ctx->pack );

  ulong payload_sz;
  /* There are two senders, one (dedup tile) which has already parsed the
     transaction, and one (gossip vote receiver in Solana Labs) which has
     not.  In either case, the transaction has already been verified.

     The dedup tile sets sig to 0, while the gossip receiver sets sig to
     1 so they can be distinguished. */

  if( FD_LIKELY( !sig ) ) {
    FD_MCNT_INC( PACK, NORMAL_TRANSACTION_RECEIVED, 1UL );
    /* Assume that the dcache entry is:
          Payload ....... (payload_sz bytes)
          0 or 1 byte of padding (since alignof(fd_txn) is 2)
          fd_txn ....... (size computed by fd_txn_footprint)
          payload_sz  (2B)
      mline->sz includes all three fields and the padding */
    payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
    uchar    const * payload = dcache_entry;
    fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );
    fd_memcpy( ctx->cur_spot->payload, payload, payload_sz                                                     );
    fd_memcpy( TXN(ctx->cur_spot),     txn,     fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) );
    ctx->cur_spot->payload_sz = payload_sz;
  } else {
    /* Here there is just a transaction payload, so it needs to be
       parsed.  We can parse right out into the pack structure. */
    FD_MCNT_INC( PACK, GOSSIPED_VOTES_RECEIVED, 1UL );
    payload_sz = sz;
    fd_memcpy( ctx->cur_spot->payload, dcache_entry, sz );
    ulong txn_t_sz = fd_txn_parse( ctx->cur_spot->payload, sz, TXN(ctx->cur_spot), NULL );
    if( FD_UNLIKELY( !txn_t_sz ) ) {
      FD_LOG_WARNING(( "fd_txn_parse failed for gossiped vote" ));
      fd_pack_insert_txn_cancel( ctx->pack, ctx->cur_spot );
      *opt_filter = 1;
      return;
    }
    ctx->cur_spot->payload_sz = payload_sz;
  }

#if DETAILED_LOGGING
  FD_LOG_NOTICE(( "Pack got a packet. Payload size: %lu, txn footprint: %lu", payload_sz,
        fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt )
      ));
#endif
}

/* After the transaction has been fully received, and we know we were
   not overrun while reading it, insert it into pack. */

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;
  long now = fd_log_wallclock();

  if( FD_UNLIKELY( in_idx==POH_IN_IDX ) ) {
    ctx->slot_end_ns = ctx->_slot_end_ns;
    fd_pack_set_block_limits( ctx->pack, ctx->slot_max_microblocks, ctx->slot_max_data );
  } else {
    /* Normal transaction case */
    long insert_duration = -fd_tickcount();
    int result = fd_pack_insert_txn_fini( ctx->pack, ctx->cur_spot, (ulong)now+TIME_OFFSET );
    insert_duration      += fd_tickcount();
    ctx->insert_result[ result + FD_PACK_INSERT_RETVAL_OFF ]++;
    fd_histf_sample( ctx->insert_duration, (ulong)insert_duration );
    if( FD_LIKELY( result>=0 ) ) ctx->last_successful_insert = now;

    ctx->cur_spot = NULL;
  }
  update_metric_state( ctx, now, FD_PACK_METRIC_STATE_TRANSACTIONS, fd_pack_avail_txn_cnt( ctx->pack )>0 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  ulong out_cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ tile->out_link_id_primary ] );

  if( FD_UNLIKELY( !out_cnt ) ) FD_LOG_ERR(( "pack tile connects to no banking tiles" ));
  if( FD_UNLIKELY( out_cnt>FD_PACK_PACK_MAX_OUT ) ) FD_LOG_ERR(( "pack tile connects to too many banking tiles" ));
  if( FD_UNLIKELY( out_cnt!=tile->pack.bank_tile_count+1UL ) ) FD_LOG_ERR(( "pack tile connects to %lu banking tiles, but tile->pack.bank_tile_count is %lu", out_cnt, tile->pack.bank_tile_count ));

  fd_pack_limits_t limits[1] = {{
    .max_cost_per_block        = tile->pack.larger_max_cost_per_block ? LARGER_MAX_COST_PER_BLOCK : FD_PACK_MAX_COST_PER_BLOCK,
    .max_vote_cost_per_block   = FD_PACK_MAX_VOTE_COST_PER_BLOCK,
    .max_write_cost_per_acct   = FD_PACK_MAX_WRITE_COST_PER_ACCT,
    .max_data_bytes_per_block  = tile->pack.larger_shred_limits_per_block ? LARGER_MAX_DATA_PER_BLOCK : FD_PACK_MAX_DATA_PER_BLOCK,
    .max_txn_per_microblock    = MAX_TXN_PER_MICROBLOCK,
    .max_microblocks_per_block = (ulong)UINT_MAX, /* Limit not known yet */
  }};

  ulong pack_footprint = fd_pack_footprint( tile->pack.max_pending_transactions, tile->pack.bank_tile_count, limits );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_pack_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  fd_rng_t *      rng = fd_rng_join( fd_rng_new( FD_SCRATCH_ALLOC_APPEND( l, fd_rng_align(), fd_rng_footprint() ), 0U, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_new failed" ));

  ctx->pack = fd_pack_join( fd_pack_new( FD_SCRATCH_ALLOC_APPEND( l, fd_pack_align(), pack_footprint ),
                                         tile->pack.max_pending_transactions, tile->pack.bank_tile_count,
                                         limits, rng ) );
  if( FD_UNLIKELY( !ctx->pack ) ) FD_LOG_ERR(( "fd_pack_new failed" ));

  ctx->cur_spot                      = NULL;
  ctx->leader_slot                   = ULONG_MAX;
  ctx->leader_bank                   = NULL;
  ctx->slot_microblock_cnt           = 0UL;
  ctx->slot_max_microblocks          = 0UL;
  ctx->slot_max_data                 = 0UL;
  ctx->larger_shred_limits_per_block = tile->pack.larger_shred_limits_per_block;
  ctx->rng                           = rng;
  ctx->last_successful_insert        = 0L;

  ctx->bank_cnt = tile->pack.bank_tile_count;
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

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  /* Initialize metrics storage */
  memset( ctx->insert_result, '\0', FD_PACK_INSERT_RETVAL_CNT * sizeof(ulong) );
  fd_histf_join( fd_histf_new( ctx->schedule_duration, FD_MHIST_SECONDS_MIN( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS ),
                                                       FD_MHIST_SECONDS_MAX( PACK, SCHEDULE_MICROBLOCK_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->insert_duration,   FD_MHIST_SECONDS_MIN( PACK, INSERT_TRANSACTION_DURATION_SECONDS  ),
                                                       FD_MHIST_SECONDS_MAX( PACK, INSERT_TRANSACTION_DURATION_SECONDS  ) ) );
  ctx->metric_state = 0;
  ctx->metric_state_begin = fd_log_wallclock();
  memset( ctx->metric_timing, '\0', 16*sizeof(long) );

  FD_LOG_INFO(( "packing microblocks of at most %lu transactions to %lu bank tiles", MAX_TXN_PER_MICROBLOCK, tile->pack.bank_tile_count ));

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static long
lazy( fd_topo_tile_t * tile ) {
  (void)tile;
  /* We want lazy (measured in ns) to be small enough that the producer
     and the consumer never have to wait for credits.  For most tango
     links, we use a default worst case speed coming from 100 Gbps
     Ethernet.  That's not very suitable for microblocks that go from
     pack to bank.  Instead we manually estimate the very aggressive
     1000ns per microblock, and then reduce it further (in line with the
     default lazy value computation) to ensure the random value chosen
     based on this won't lead to credit return stalls. */
  return 128L * 300L;
}


static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_pack( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_pack_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_pack = {
  .name                     = "pack",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_credit        = before_credit,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_metrics_write        = metrics_write,
  .lazy                     = lazy,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
};
