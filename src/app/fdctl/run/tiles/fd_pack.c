#include "tiles.h"

#include "../../../../ballet/pack/fd_pack.h"

#include <linux/unistd.h>

/* fd_pack is responsible for taking verified transactions, and
   arranging them into "microblocks" (groups) of transactions to
   be executed serially.  It can try to do clever things so that
   multiple microblocks can execute in parallel, if they don't
   write to the same accounts. */

#define LSCHED_IN_IDX (2UL)

#define MAX_SLOTS_PER_EPOCH          432000UL
#define NUM_CONSECUTIVE_LEADER_SLOTS 4UL

#define SET_NAME lsched_bitset
#define SET_MAX ((MAX_SLOTS_PER_EPOCH)/(NUM_CONSECUTIVE_LEADER_SLOTS))
#include "../../../../util/tmpl/fd_set.c"

#define BLOCK_DURATION_NS (400UL*1000UL*1000UL)

/* About 1.5 kB on the stack */
#define FD_PACK_PACK_MAX_OUT (16UL)

#define MAX_TXN_PER_MICROBLOCK (MAX_MICROBLOCK_SZ/sizeof(fd_txn_p_t))

/* in bytes.  Defined this way to use the size field of mcache */
#define MAX_MICROBLOCK_SZ USHORT_MAX

/* 1.5 M cost units, enough for 1 max size transaction */
const ulong CUS_PER_MICROBLOCK = 1500000UL;

const float VOTE_FRACTION = 0.75;

struct bit_lsched {
  ulong epoch;
  ulong start_slot;
  ulong slot_cnt;
  lsched_bitset_t lsched[ lsched_bitset_word_cnt ];
};
typedef struct bit_lsched bit_lsched_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_pack_in_ctx_t;

typedef struct {
  fd_pack_t *  pack;
  fd_txn_p_t * cur_spot;

  long block_duration_ticks;
  long block_end;

  fd_acct_addr_t identity_pubkey __attribute__((aligned(32UL)));

  /* These point to memory, each which is written atomically by the PoH recorder */
  ulong * _poh_slot;
  ulong * _poh_reset_slot;
  /* And these are our local copies, updated in the housekeeping loop to
     limit cache ping-ponging. */
  ulong poh_slot;
  ulong poh_reset_slot;
  int   poh_slots_updated;

  ulong packing_for; /* The slot for which we are producing microblocks, or ULONG_MAX if we aren't leader. */

  /* Keep two leader schedules around for the transition between epochs,
     and a third for speculative processing.  The following three
     pointers jump around between the three elements of _lsched as the
     epochs progress. */
  bit_lsched_t * even_epoch_lsched;
  bit_lsched_t * odd_epoch_lsched;
  bit_lsched_t * spare_lsched;
  bit_lsched_t   _lsched[ 3 ];

  fd_pack_in_ctx_t in[ 32 ];

  ulong    out_cnt;
  ulong *  out_busy[ FD_PACK_PACK_MAX_OUT ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_pack_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  SCRATCH_ALLOC( fd_rng_align(),           fd_rng_footprint() );
  SCRATCH_ALLOC( fd_pack_align(), fd_pack_footprint( tile->pack.max_pending_transactions,
                                                     tile->pack.bank_tile_count,
                                                     MAX_TXN_PER_MICROBLOCK ) );
  return fd_ulong_align_up( scratch_top, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_pack_ctx_t ) );
}

static inline void
during_housekeeping( void * _ctx ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  ulong new_poh_slot   = FD_VOLATILE_CONST( *(ctx->_poh_slot      ) );
  ulong new_reset_slot = FD_VOLATILE_CONST( *(ctx->_poh_reset_slot) );
  if( FD_UNLIKELY( (new_poh_slot!=ctx->poh_slot) | (new_reset_slot!=ctx->poh_reset_slot) ) ) {
    ctx->poh_slot          = new_poh_slot;
    ctx->poh_reset_slot    = new_reset_slot;
    ctx->poh_slots_updated  = 1; /* Handle all the state transitions in before_credit below */
  }
}

static inline int
am_i_leader( fd_pack_ctx_t * ctx,
             ulong           slot ) {
  bit_lsched_t const * even = ctx->even_epoch_lsched;
  bit_lsched_t const * odd  = ctx->odd_epoch_lsched;

  int is_even = (even->start_slot <= slot) & (slot-even->start_slot < even->slot_cnt);
  int is_odd  = (odd->start_slot  <= slot) & (slot-odd->start_slot  < odd->slot_cnt);

  if( FD_UNLIKELY( !(is_even | is_odd) ) ) {
    FD_LOG_WARNING(( "Tried to query the leader for slot %lu, but we only knew about epochs: "
          "%lu slots [%lu, %lu), and %lu slots [%lu, %lu)",
          slot, even->epoch, even->start_slot, even->start_slot + even->slot_cnt,
          odd->epoch, odd->start_slot, odd->start_slot + odd->slot_cnt ));
    return 0;
  }

  ulong offset = (slot - fd_ulong_if( is_even, even->start_slot, odd->start_slot )) / NUM_CONSECUTIVE_LEADER_SLOTS;

  return lsched_bitset_test( fd_ptr_if( is_even, even, odd )->lsched, offset );
}

static inline int
should_pack( fd_pack_ctx_t * ctx,
             ulong           current_slot,
             ulong           reset_slot    ) {
  /* Optimize for the case that we are becoming leader even though it's
     statistically infrequent. */
  if( FD_LIKELY( am_i_leader( ctx, current_slot ) ) ) {
    /* If reset_slot and current_slot are the same, that means the
       banking stage has received and fully processed the last tick in
       the previous leader's block, so there's no need to continue
       waiting grace ticks.

       If it has been more than 4 slots since the last block, then
       probably the previous leader just didn't produce anything, so we
       don't wait grace ticks either.

       If I'm leader for slot 0, grace ticks don't make any sense, so
       just start packing now.

       If I was leader in the previous slot (which we know exists since
       it's not slot 0), then either I was packing in the previous slot,
       or I've already waited a full slot worth of grace ticks.  Either
       way, now I can start packing.  Solana Labs's code seems to try to
       give two slots of grace ticks, but actually ends up only giving
       one, so we also only give one. */
    if( FD_LIKELY  ( current_slot==reset_slot            ) ) return 1;
    if( FD_UNLIKELY( current_slot>=reset_slot + 4UL      ) ) return 1;
    if( FD_UNLIKELY( current_slot==0UL                   ) ) return 1;
    if( FD_LIKELY  ( am_i_leader( ctx, current_slot-1UL )) ) return 1;
  }
  /* Either I'm not the leader for this slot or I need to give the
     previous leader grace ticks. */
  return 0;
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

  /* There are two things that can cause a transition in our leader
     state machine: observing a poh_slot/poh_reset_slot update, and the
     block timeout expiring. */

  /* Block timeout.  When we're not leader, block_end is LONG_MAX, so
     this will never be true. */
  long now = fd_tickcount();
  ulong initial_packing_for = ctx->packing_for;

  if( FD_UNLIKELY( (now-ctx->block_end)>=0L ) ) {
    /* Temporarily pause packing until we observe PoH advance */
    ctx->block_end   = LONG_MAX;
    ctx->packing_for = ULONG_MAX;
  }
  /* Slot update */
  if( FD_UNLIKELY( ctx->poh_slots_updated ) ) {
    ctx->poh_slots_updated = 0;

    /* Optimize for the non-leader -> leader transition */
    if( FD_LIKELY( should_pack( ctx, ctx->poh_slot, ctx->poh_reset_slot ) ) ) {
      if( FD_UNLIKELY( (ctx->packing_for==ULONG_MAX) | (ctx->poh_slot>ctx->packing_for) ) ) {
        /* Handle transition from non-leader to leader or transition
           from leader to the next leader slot that happened after the
           timeout triggered. */
        ctx->packing_for = ctx->poh_slot;
        ctx->block_end   = fd_tickcount() + ctx->block_duration_ticks;
      }
    } else {
      /* I'm no longer leader */
      ctx->block_end   = LONG_MAX;
      ctx->packing_for = ULONG_MAX;
    }
  }

  if( FD_UNLIKELY( ctx->packing_for != initial_packing_for ) ) fd_pack_end_block( ctx->pack );
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  /* Am I leader? If not, nothing to do. */
  if( FD_UNLIKELY( ctx->packing_for == ULONG_MAX ) ) return;

  /* Is it time to schedule the next microblock? For each banking
     thread, if it's not busy... */
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    if( FD_LIKELY( fd_fseq_query( ctx->out_busy[i] ) == *mux->seq ) ) { /* optimize for the case we send a microblock */
      fd_pack_microblock_complete( ctx->pack, i );

      void * microblock_dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      ulong schedule_cnt = fd_pack_schedule_next_microblock( ctx->pack, CUS_PER_MICROBLOCK, VOTE_FRACTION, i, microblock_dst );
      if( FD_LIKELY( schedule_cnt ) ) {
        ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        ulong chunk  = ctx->out_chunk;
        ulong msg_sz = schedule_cnt*sizeof(fd_txn_p_t);

        /* The low byte of the signature field is the bank idx.  Banks
           will filter to only handle frags with their own idx.  The
           higher 7 bytes are the slot number.  Technically, the slot
           number is a ulong, but it won't hit 256^7 for about 10^9
           years at the current rate. */
        ulong sig = (ctx->packing_for << 8) | (i & 0xFFUL);
        fd_mux_publish( mux, sig, chunk, msg_sz, 0, 0UL, tspub );

        ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, msg_sz, ctx->out_chunk0, ctx->out_wmark );
      }
    }
  }
}

/* At this point, we have started receiving frag seq with details in
    mline at time now.  Speculatively processs it here. */

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz > FD_TPU_DCACHE_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk );

  if( FD_UNLIKELY( in_idx == LSCHED_IN_IDX ) ) {
    bit_lsched_t * new_lsched = ctx->spare_lsched;
    lsched_bitset_t * bit = lsched_bitset_join( lsched_bitset_new( new_lsched->lsched ) );

    ulong * hdr = (ulong *)dcache_entry;
    new_lsched->epoch      = hdr[ 0 ];
    new_lsched->start_slot = hdr[ 1 ];
    new_lsched->slot_cnt   = hdr[ 2 ] - hdr[ 1 ];

    ulong offset = 3UL*sizeof(ulong);
    for( ulong i=0UL; i<new_lsched->slot_cnt; i+=NUM_CONSECUTIVE_LEADER_SLOTS ) {
      lsched_bitset_insert_if( bit, !memcmp( dcache_entry+offset, ctx->identity_pubkey.b, 32UL ), i/NUM_CONSECUTIVE_LEADER_SLOTS );
      offset += NUM_CONSECUTIVE_LEADER_SLOTS * 32UL;
    }

    return;
  }

  ctx->cur_spot              = fd_pack_insert_txn_init( ctx->pack );

  ulong payload_sz;
  /* There are two senders, one (dedup tile) which has already parsed the
     transaction, and one (gossip vote receiver in Solana Labs) which has
     not.  In either case, the transaction has already been verified.

     The dedup tile sets sig to 0, while the gossip receiver sets sig to
     1 so they can be distinguished. */

  if( FD_LIKELY( !sig ) ) {
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
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;

  fd_pack_ctx_t * ctx = (fd_pack_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx == LSCHED_IN_IDX ) ) {
    /* Swap the spare leader schedule we just populated into the spot
       where it belongs. */
    bit_lsched_t * temp;
    ulong new_epoch = ctx->spare_lsched->epoch;
    if( ctx->spare_lsched->epoch & 1 ) {
      temp = ctx->odd_epoch_lsched;
      ctx->odd_epoch_lsched = ctx->spare_lsched;
    } else {
      temp = ctx->even_epoch_lsched;
      ctx->even_epoch_lsched = ctx->spare_lsched;
    }
    ctx->spare_lsched = temp;
    lsched_bitset_delete( lsched_bitset_leave( temp->lsched ) );

    /* The leader schedule for the first two epochs is always the
       singular bootstrap validator chosen at genesis, so we fabricate
       the leader schedule for epoch 0 from epoch 1. */
    if( FD_UNLIKELY( new_epoch==1UL ) ) {
      bit_lsched_t * new_lsched = temp;
      lsched_bitset_t * bit = lsched_bitset_join( lsched_bitset_new( new_lsched->lsched ) );

      new_lsched->epoch      = 0UL;
      new_lsched->start_slot = 0UL;
      new_lsched->slot_cnt   = ctx->odd_epoch_lsched->start_slot; /* must be epoch 1 */

      /* Fill epoch 0 with the bit from the first slot of epoch 1. */
      lsched_bitset_full_if( bit, lsched_bitset_test( ctx->odd_epoch_lsched->lsched, 0UL ) );

      temp = ctx->even_epoch_lsched;
      ctx->even_epoch_lsched = new_lsched;
      ctx->spare_lsched = temp;
      lsched_bitset_delete( lsched_bitset_leave( temp->lsched ) );
    }

  } else {
    /* Normal transaction case */
    fd_pack_insert_txn_fini( ctx->pack, ctx->cur_spot );
    ctx->cur_spot = NULL;
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  ulong scratch_top = (ulong)scratch;
  fd_pack_ctx_t * ctx = SCRATCH_ALLOC( alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->pack.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  /* This seems like overkill for just the public key, but it's not
     really easy to load just the public key without also getting the
     private key. */
  void const * identity_pubkey = load_key_into_protected_memory( tile->pack.identity_key_path, 1 /* public_key_only */ );
  ctx->identity_pubkey = *(fd_acct_addr_t const *)identity_pubkey;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  ulong out_cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ tile->out_link_id_primary ] );

  if( FD_UNLIKELY( !out_cnt ) ) FD_LOG_ERR(( "pack tile connects to no banking tiles" ));
  if( FD_UNLIKELY( out_cnt>FD_PACK_PACK_MAX_OUT ) ) FD_LOG_ERR(( "pack tile connects to too many banking tiles" ));
  if( FD_UNLIKELY( out_cnt!=tile->pack.bank_tile_count ) ) FD_LOG_ERR(( "pack tile connects to %lu banking tiles, but tile->pack.bank_tile_count is %lu", out_cnt, tile->pack.bank_tile_count ));

  ulong pack_footprint = fd_pack_footprint( tile->pack.max_pending_transactions, out_cnt, MAX_TXN_PER_MICROBLOCK );

  ulong scratch_top = (ulong)scratch;
  fd_pack_ctx_t * ctx = (fd_pack_ctx_t*)SCRATCH_ALLOC( alignof( fd_pack_ctx_t ), sizeof( fd_pack_ctx_t ) );
  fd_rng_t *      rng = fd_rng_join( fd_rng_new( SCRATCH_ALLOC( fd_rng_align(), fd_rng_footprint() ), 0U, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_new failed" ));

  ctx->pack = fd_pack_join( fd_pack_new( SCRATCH_ALLOC( fd_pack_align(), pack_footprint ), tile->pack.max_pending_transactions, out_cnt, MAX_TXN_PER_MICROBLOCK, rng ) );
  if( FD_UNLIKELY( !ctx->pack ) ) FD_LOG_ERR(( "fd_pack_new failed" ));

  ctx->cur_spot = NULL;
  ctx->block_duration_ticks = (long)(fd_tempo_tick_per_ns( NULL ) * (double)BLOCK_DURATION_NS);
  ctx->block_end = LONG_MAX;

  if( FD_UNLIKELY( (!tile->extra[0]) | (!tile->extra[1]) ) ) FD_LOG_ERR(( "poh_slot and/or poh_reset_slot not configured" ));
  ctx->_poh_slot       = tile->extra[0];
  ctx->_poh_reset_slot = tile->extra[1];
  ctx->poh_slot          = 0UL;
  ctx->poh_reset_slot    = 0UL;
  ctx->poh_slots_updated = 0;

  ctx->packing_for = ULONG_MAX;
  ctx->even_epoch_lsched = ctx->_lsched + 0;
  ctx->odd_epoch_lsched  = ctx->_lsched + 1;
  ctx->spare_lsched      = ctx->_lsched + 2;
  ctx->even_epoch_lsched->slot_cnt = 0UL;
  ctx->odd_epoch_lsched->slot_cnt  = 0UL;

  ctx->out_cnt  = out_cnt;
  for( ulong i=0; i<out_cnt; i++ ) {
    ctx->out_busy[ i ] = tile->extra[ i ];
    if( FD_UNLIKELY( !ctx->out_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
  }

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  FD_LOG_INFO(( "packing blocks of at most %lu transactions to %lu bank tiles", MAX_TXN_PER_MICROBLOCK, out_cnt ));

  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static ulong
allow_fds( void * scratch,
           ulong  out_fds_cnt,
           int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t fd_tile_pack = {
  .mux_flags               = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                   = 1UL,
  .mux_ctx                 = mux_ctx,
  .mux_during_housekeeping = during_housekeeping,
  .mux_before_credit       = before_credit,
  .mux_after_credit        = after_credit,
  .mux_during_frag         = during_frag,
  .mux_after_frag          = after_frag,
  .allow_syscalls_cnt      = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls          = allow_syscalls,
  .allow_fds               = allow_fds,
  .scratch_align           = scratch_align,
  .scratch_footprint       = scratch_footprint,
  .privileged_init         = privileged_init,
  .unprivileged_init       = unprivileged_init,
};
