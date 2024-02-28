#include "fd_poh_tile.h"

#include "../../keyguard/fd_keyload.h"
#include "../../shred/fd_shredder.h"
#include "../../bank/fd_bank_abi.h"
#include "../../metrics/generated/fd_metrics_poh.h"

#include "../../../ballet/pack/fd_pack.h"
#include "../../../ballet/bmtree/fd_bmtree.h"
#include "../../../flamenco/leaders/fd_leaders.h"

/* When we are becoming leader, and we think the prior leader might have
   skipped their slot, we give them a grace period to finish.  In the
   Solana Labs client this is called grace ticks.  This is a courtesy to
   maintain network health, and is not strictly necessary.  It is
   actually advantageous to us as new leader to take over right away and
   give no grace period, since we could generate more fees.

   Here we define the grace period to be two slots, which is taken from
   Solana Labs directly. */

#define GRACE_SLOTS (2UL)

/* The PoH recorder is implemented in Firedancer but for now needs to
   work with Solana Labs, so we have a locking scheme for them to
   co-operate.

   This is because the PoH tile lives in the Solana Labs memory address
   space and their version of concurrency is locking the PoH recorder
   and reading arbitrary fields.

   So we allow them to lock the PoH tile, although with a very bad (for
   them) locking scheme.  By default, the tile has full and exclusive
   access to the data.  If part of Solana Labs wishes to read/write they
   can either,

     1. Rewrite their concurrency to message passing based on mcache
        (preferred, but not feasible).
     2. Signal to the tile they wish to acquire the lock, by setting
        fd_poh_waiting_lock to 1.

   During housekeeping, the tile will check if there is the waiting lock
   is set to 1, and if so, set the returned lock to 1, indicating to the
   waiter that they may now proceed.

   When the waiter is done reading and writing, they restore the
   returned lock value back to zero, and the POH tile continues with its
   day. */

static fd_poh_tile_t * fd_poh_global_ctx;

static volatile ulong fd_poh_waiting_lock __attribute__((aligned(128UL)));
static volatile ulong fd_poh_returned_lock __attribute__((aligned(128UL)));

static fd_poh_tile_t *
fd_ext_poh_write_lock( void ) {
  for(;;) {
    /* Acquire the waiter lock to make sure we are the first writer in the queue. */
    if( FD_LIKELY( !FD_ATOMIC_CAS( &fd_poh_waiting_lock, 0UL, 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  for(;;) {
    /* Now wait for the tile to tell us we can proceed. */
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_poh_returned_lock ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  return fd_poh_global_ctx;
}

static void
fd_ext_poh_write_unlock( void ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fd_poh_returned_lock ) = 0UL;
}

/* The PoH tile needs to interact with the Solana Labs address space to
   do certain operations that Firedancer hasn't reimplemented yet, a.k.a
   transaction execution.  We have Solana Labs export some wrapper
   functions that we call into during regular tile execution.  These do
   not need any locking, since they are called serially from the single
   PoH tile. */

extern void fd_ext_bank_commit_txns( void const * bank, void const * txns, ulong txn_cnt , void * load_and_execute_output, void * pre_balance_info );
extern void fd_ext_bank_acquire( void const * bank );
extern void fd_ext_bank_release( void const * bank );
extern void fd_ext_bank_release_thunks( void * load_and_execute_output );
extern void fd_ext_bank_release_pre_balance_info( void * pre_balance_info );
extern void fd_ext_poh_signal_leader_change( void * sender );
extern void fd_ext_poh_register_tick( void const * bank, uchar const * hash );

/* fd_ext_poh_initialize is called by Solana Labs on startup to
   initialize the PoH tile with some static configuration, and the
   initial reset slot and hash which it retrieves from a snapshot.

   This function is called by some random Solana Labs thread, but
   it blocks booting of the PoH tile.  The tile will spin until it
   determines that this initialization has happened.

   signal_leader_change is an opaque Rust object that is used to
   tell the replay stage that the leader has changed.  It is a
   Box::into_raw(Arc::increment_strong(crossbeam::Sender)), so it
   has infinite lifetime unless this C code releases the refcnt.

   It can be used with `fd_ext_poh_signal_leader_change` which
   will just issue a nonblocking send on the channel. */

void
fd_ext_poh_initialize( ulong         hashcnt_duration_ns, /* See clock comments above, will be 500ns for mainnet-beta. */
                       ulong         hashcnt_per_tick,    /* See clock comments above, will be 12,500 for mainnet-beta. */
                       ulong         ticks_per_slot,      /* See clock comments above, will almost always be 64. */
                       ulong         tick_height,         /* The counter (height) of the tick to start hashing on top of. */
                       uchar const * last_entry_hash,     /* Points to start of a 32 byte region of memory, the hash itself at the tick height. */
                       void *        signal_leader_change /* See comment above. */ ) {
  FD_COMPILER_MFENCE();
  for(;;) {
    /* Make sure the ctx is initialized before trying to take the lock. */
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_poh_global_ctx ) ) ) break;
    FD_SPIN_PAUSE();
  }
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();
  
  ctx->hashcnt             = tick_height*hashcnt_per_tick;
  ctx->last_hashcnt        = ctx->hashcnt;
  ctx->reset_slot_hashcnt  = ctx->hashcnt;
  ctx->reset_slot_start_ns = fd_log_wallclock();

  fd_memcpy( ctx->hash, last_entry_hash, 32UL );

  ctx->signal_leader_change = signal_leader_change;

  /* Store configuration about the clock. */
  ctx->hashcnt_duration_ns = hashcnt_duration_ns;
  ctx->hashcnt_per_tick = hashcnt_per_tick;
  ctx->ticks_per_slot = ticks_per_slot;

  /* Can be derived from other information, but we precompute it
     since it is used frequently. */
  ctx->hashcnt_per_slot = ticks_per_slot*hashcnt_per_tick;

  fd_ext_poh_write_unlock();
}

/* fd_ext_poh_acquire_bank gets the current leader bank if there is one
   currently active.  PoH might think we are leader without having a
   leader bank if the replay stage has not yet noticed we are leader.

   The bank that is returned is owned the caller, and must be converted
   to an Arc<Bank> by calling Arc::from_raw() on it.  PoH increments the
   reference count before returning the bank, so that it can also keep
   its internal copy.

   If there is no leader bank, NULL is returned.  In this case, the
   caller should not call `Arc::from_raw()`. */

void const *
fd_ext_poh_acquire_leader_bank( void ) {
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();
  void const * bank = NULL;
  if( FD_LIKELY( ctx->current_leader_bank ) ) {
    /* Clone refcount before we release the lock. */
    fd_ext_bank_acquire( ctx->current_leader_bank );
    bank = ctx->current_leader_bank;
  }
  fd_ext_poh_write_unlock();
  return bank;
}

/* fd_ext_poh_reset_slot returns the slot height one above the last good
   (unskipped) slot we are building on top of.  This is always a good
   known value, and will not be ULONG_MAX. */

ulong
fd_ext_poh_reset_slot( void ) {
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();
  ulong reset_slot = ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot;
  fd_ext_poh_write_unlock();
  return reset_slot;
}

/* fd_ext_poh_reached_leader_slot returns 1 if we have reached a slot
   where we are leader.  This is used by the replay stage to determine
   if it should create a new leader bank descendant of the prior reset
   slot block. 
   
   Sometimes, even when we reach our slot we do not return 1, as we are
   giving a grace period to the prior leader to finish publishing their
   block. 
   
   out_leader_slot is the slot height of the leader slot we reached, and
   reset_slot is the slot height of the last good (unskipped) slot we
   are building on top of. */

int
fd_ext_poh_reached_leader_slot( ulong * out_leader_slot,
                                ulong * out_reset_slot ) {
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();

  ulong slot = ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot;
  *out_leader_slot = slot;
  *out_reset_slot = ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot;

  if( FD_UNLIKELY( ctx->next_leader_slot_hashcnt==ULONG_MAX ||
                   ctx->hashcnt<ctx->next_leader_slot_hashcnt ) ) {
    /* Didn't reach our leader slot yet. */
    fd_ext_poh_write_unlock();
    return 0;
  }

  if( FD_LIKELY( ctx->reset_slot_hashcnt==ctx->next_leader_slot_hashcnt ) ) {
    /* We were reset onto our leader slot, because the prior leader
       completed theirs, so we should start immediately, no need for a
       grace period. */
    fd_ext_poh_write_unlock();
    return 1;
  }

  if( FD_LIKELY( slot>=1UL ) ) {
    fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, slot-1UL );
    if( FD_LIKELY( leaders ) ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, slot-1UL );
      if( FD_LIKELY( leader ) ) {
        if( FD_UNLIKELY( !memcmp( leader->uc, ctx->identity_key.uc, 32UL ) ) ) {
          /* We were the leader in the previous slot, so also no need for
            a grace period.  We wouldn't get here if we were still
            processing the prior slot so begin new one immediately. */
          fd_ext_poh_write_unlock();
          return 1;
        }
      }
    }
  }

  ulong reset_slot = ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot;
  if( FD_UNLIKELY( slot-reset_slot>=4UL ) ) {
    /* The prior leader has not completed any slot successfully during
       their 4 leader slots, so they are probably inactive and no need
       to give a grace period. */
    fd_ext_poh_write_unlock();
    return 1;
  }

  if( FD_LIKELY( (ctx->hashcnt-ctx->next_leader_slot_hashcnt) < GRACE_SLOTS * ctx->hashcnt_per_slot ) ) {
    /*  The prior leader hasn't finished their last slot, and they are
        likely still publishing, and within their grace period of two
        slots so we will keep waiting. */
    fd_ext_poh_write_unlock();
    return 0;
  }

  fd_ext_poh_write_unlock();
  return 1;
}

/* The PoH tile knows when it should become leader by waiting for its
   leader slot (with the operating system clock).  This function is so
   that when it becomes the leader, it can be told what the leader bank
   is by the replay stage.  See the notes in the long comment above for
   more on how this works. */

void
fd_ext_poh_begin_leader( void const * bank,
                         ulong        slot ) {
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();

  if( FD_UNLIKELY( ctx->current_leader_bank ) ) fd_ext_bank_release( ctx->current_leader_bank );
  ctx->current_leader_bank = NULL;

  ulong current_slot = ctx->hashcnt/ctx->hashcnt_per_slot;
  if( FD_UNLIKELY( slot!=current_slot ) ) {
    /* Already timed out.. nothing to do. */
    if( FD_LIKELY( slot<current_slot ) ) FD_MCNT_INC( POH_TILE, REPLAY_TOO_EARLY, 1UL );
    else                                 FD_MCNT_INC( POH_TILE, REPLAY_TOO_LATE, 1UL );

    fd_ext_poh_write_unlock();
    return;
  }

  ulong leader_slot = ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot;
  if( FD_UNLIKELY( slot!=leader_slot ) ) {
    /* Super rare race condition that probably can't happen. The replay
       stage asked if we are leader in this slot, and we said yes, so
       it created a leader bank and calls into PoH to tell it the bank,
       and now we don't think we are leader anymore.  PoH is probably
       correct in this case, so just miss the slot, and let fork
       selection figure it out. */
    FD_MCNT_INC( POH_TILE, REPLAY_NO_LONGER_LEADER, 1UL );
    fd_ext_poh_write_unlock();
    return;
  }

  ctx->current_leader_bank = bank;
  ctx->send_leader_now_for_slot = slot;

  fd_ext_poh_write_unlock();
}

/* Determine what the next slot is in the leader schedule is that we are
   leader.  Includes the current slot.  If we are not leader in what
   remains of the current and next epoch, return ULONG_MAX. */

static inline ulong
next_leader_slot_hashcnt( fd_poh_tile_t * ctx ) {
  ulong current_slot = ctx->hashcnt/ctx->hashcnt_per_slot;
  /* If we have published anything in a particular slot, then we
     should never become leader for that slot again.

     last_hashcnt is always recorded after incrementing the
     hashcnt (after publishing) for the tick or entry, so
     to get the slot we published in, it is

        (ctx->last_hashcnt-1UL)/ctx->hashcnt_per_slot

     Then we have to add one to get the next slot that we are
     allowed to publish for. */
  current_slot = fd_ulong_max( current_slot, 1UL+(ctx->last_hashcnt-1UL)/ctx->hashcnt_per_slot );

  for(;;) {
    fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, current_slot );
    if( FD_UNLIKELY( !leaders ) ) break;

    while( current_slot<(leaders->slot0+leaders->slot_cnt) ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, current_slot );
      if( FD_UNLIKELY( !memcmp( leader->key, ctx->identity_key.key, 32UL ) ) ) return current_slot*ctx->hashcnt_per_slot;
      current_slot++;
    }
  }

  return ULONG_MAX;
}

static void
no_longer_leader( fd_poh_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->current_leader_bank ) ) fd_ext_bank_release( ctx->current_leader_bank );
  ctx->current_leader_bank = NULL;
  ctx->next_leader_slot_hashcnt = next_leader_slot_hashcnt( ctx );
  if( FD_UNLIKELY( ctx->send_leader_now_for_slot!=ULONG_MAX ) ) {
    FD_MCNT_INC( POH_TILE, LEADER_SLOT_MISSED_BACKPRESSURE, 1UL );
    ctx->send_leader_now_for_slot = ULONG_MAX;
  }
  FD_COMPILER_MFENCE();
  fd_ext_poh_signal_leader_change( ctx->signal_leader_change );
  FD_LOG_INFO(( "no_longer_leader(next_leader_slot=%lu)", ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot ));
}

/* fd_ext_poh_reset is called by the Solana Labs client when a slot on
   the active fork has finished a block and we need to reset our PoH to
   be ticking on top of the block it produced. */

void
fd_ext_poh_reset( ulong         reset_bank_slot, /* The slot that successfully produced a block */
                  uchar const * reset_blockhash  /* The hash of the last tick in the produced block */ ) {
  fd_poh_tile_t * ctx = fd_ext_poh_write_lock();

  int leader_before_reset = ctx->hashcnt>=ctx->next_leader_slot_hashcnt;

  fd_memcpy( ctx->hash, reset_blockhash, 32UL );
  ctx->hashcnt             = (reset_bank_slot+1UL)*ctx->hashcnt_per_slot;
  ctx->last_hashcnt        = ctx->hashcnt;
  ctx->reset_slot_hashcnt  = ctx->hashcnt;
  ctx->reset_slot_start_ns = fd_log_wallclock();

  if( FD_UNLIKELY( leader_before_reset ) ) {
    /* No longer have a leader bank if we are reset. Replay stage will
       call back again to give us a new one if we should become leader
       for the reset slot.
       
       The order is important here, ctx->hashcnt must be updated before
       calling no_longer_leader. */
    no_longer_leader( ctx );
  }
  ctx->next_leader_slot_hashcnt = next_leader_slot_hashcnt( ctx );
  FD_LOG_INFO(( "fd_ext_poh_reset(slot=%lu,next_leader_slot=%lu)", ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot, ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot ));

  fd_ext_poh_write_unlock();
}

FD_FN_CONST ulong
fd_poh_tile_align( void ) {
  return FD_POH_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_poh_tile_footprint( fd_poh_tile_args_t const * args ) {
  (void)args;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_poh_tile_t ), sizeof( fd_poh_tile_t ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, FD_SHA256_ALIGN, FD_SHA256_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  return FD_LAYOUT_FINI( l, fd_poh_tile_align() );
}

static void
publish_became_leader( fd_poh_tile_t *    ctx,
                       fd_mux_context_t * mux ) {
  ulong leader_start_hashcnt = ctx->send_leader_now_for_slot*ctx->hashcnt_per_slot;
  long slot_start_ns = ctx->reset_slot_start_ns + (long)((leader_start_hashcnt-ctx->reset_slot_hashcnt)*ctx->hashcnt_duration_ns);

  for( ulong i=0UL; i<ctx->bank_cnt; i++ ) {
    /* Kind of a hack.  Each bank tile gets a strong refcnt on the
       bank which they will release once they have seen all the
       transactions for it.  We can't pass the refcnt to the pack
       tile since it does not live in Solana address space and
       won't be able to decrement it. */
    fd_ext_bank_acquire( ctx->current_leader_bank );
  }

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_became_leader_t * leader = (fd_became_leader_t *)dst;
  leader->slot_start_ns = slot_start_ns;
  leader->bank = ctx->current_leader_bank;
  ulong sig = fd_disco_poh_sig( ctx->send_leader_now_for_slot, POH_PKT_TYPE_BECAME_LEADER, 0UL );
  fd_mux_publish( mux, sig, ctx->out_chunk, sizeof(fd_became_leader_t), 0UL, 0UL, 0UL );
  ctx->send_leader_now_for_slot = ULONG_MAX;
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_became_leader_t), ctx->out_chunk0, ctx->out_wmark );
}

static void
publish_tick( fd_poh_tile_t *    ctx,
              fd_mux_context_t * mux ) {
  /* We must subtract 1 from hascnt here, since we might have ticked
     over into the next slot already. */
  ulong slot = (ctx->hashcnt-1UL)/ctx->hashcnt_per_slot;

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  meta->parent_offset = 1UL + slot - (ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot);
  ulong slot_hashcnt = slot*ctx->hashcnt_per_slot;
  meta->reference_tick = (ctx->hashcnt-slot_hashcnt)/ctx->hashcnt_per_tick;

  meta->block_complete = !(ctx->hashcnt % ctx->hashcnt_per_slot);

  ulong hash_delta = ctx->hashcnt - ctx->last_hashcnt;
  ctx->last_hashcnt = ctx->hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * tick = (fd_entry_batch_header_t *)dst;
  tick->hashcnt_delta = hash_delta;
  fd_memcpy( tick->hash, ctx->hash, 32UL );
  tick->txn_cnt = 0UL;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t);
  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  fd_mux_publish( mux, sig, ctx->out_chunk, sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_poh_tile_t * ctx = (fd_poh_tile_t *)_ctx;

  if( FD_LIKELY( ctx->send_leader_now_for_slot!=ULONG_MAX ) ) {
    /* If the replay stage gave us the bank for the current leader slot,
      we should now send a frag to the pack tile telling it that it can
      start packing. */
    publish_became_leader( ctx, mux );
  }

  int is_leader = ctx->next_leader_slot_hashcnt!=ULONG_MAX && ctx->hashcnt>=ctx->next_leader_slot_hashcnt;
  if( FD_UNLIKELY( is_leader && !ctx->current_leader_bank ) ) {
    /* If we are the leader, but we didn't yet learn what the leader
       bank object is from the replay stage, do not do any hashing.
       
       This is not ideal, but greatly simplifies the control flow. */
    return;
  }

  /* Now figure out how many hashes are needed to "catch up" the hash
     count to the current system clock. */
  long now = fd_log_wallclock();
  ulong target_hash_cnt = ctx->reset_slot_hashcnt + (ulong)(now - ctx->reset_slot_start_ns) / ctx->hashcnt_duration_ns;

  /* And then now actually perform the hashes.

     Recall that there are two kinds of events that will get published
     to the shredder,

       (a) Ticks. These occur every 12,500 (hashcnt_per_tick) hashcnts,
           and there will be 64 (ticks_per_slot) of them in each slot.
           
           Ticks must not have any transactions mixed into the hash.
           This is not strictly needed in theory, but is required by the
           current consensus protocol.

       (b) Microblocks.  These can occur at any other hashcnt, as long
           as it is not a tick.  Microblocks cannot be empty, and must
           have at least one transactions mixed in.

     To make sure that we do not publish microblocks on tick boundaries,
     we always make sure here the hashcnt does not get left one before
     a tick boundary.  If we reach such a case and want to terminate the
     loop, we simply do one more hash and publish the tick first.

     If hashcnt_per_tick is 1, then we are in low power mode and this
     does not apply, we can mix in transactions at any time. */
  while( ctx->hashcnt<target_hash_cnt || (ctx->hashcnt_per_tick!=1UL && (ctx->hashcnt_per_tick-1UL)==(ctx->hashcnt%ctx->hashcnt_per_tick)) ) {
    fd_sha256_hash( ctx->hash, 32UL, ctx->hash );
    ctx->hashcnt++;

    if( FD_UNLIKELY( is_leader && !(ctx->hashcnt%ctx->hashcnt_per_tick) ) ) {
      /* We ticked while leader... tell the leader bank. */
      fd_ext_poh_register_tick( ctx->current_leader_bank, ctx->hash );

      /* And send an empty microblock (a tick) to the shred tile. */
      publish_tick( ctx, mux );
    }

    if( FD_UNLIKELY( is_leader && ctx->hashcnt>=(ctx->next_leader_slot_hashcnt+ctx->hashcnt_per_slot) ) ) {
      /* We ticked while leader and are no longer leader... transition
         the state machine. */
      no_longer_leader( ctx );
    }

    if( FD_UNLIKELY( !(ctx->hashcnt%ctx->hashcnt_per_tick) ) ) {
      /* If we ticked at all, we need to abort the loop if we were
         leader since otherwise we could consume infinite credits
         to publish here.  The credits are set so that we should
         only ever publish one tick during this loop.

         We could keep turning the loop here if we are not leader,
         as we didn't publish a frag yet, but it's better to just
         bound the loop and let housekeeping and other frag polling
         run anyway. */
      break;
    }
  }
}

static inline void
during_housekeeping( void * ctx ) {
  (void)ctx;

  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( fd_poh_waiting_lock ) )  {
    FD_VOLATILE( fd_poh_returned_lock ) = 1UL;
    FD_COMPILER_MFENCE();
    for(;;) {
      if( FD_UNLIKELY( !FD_VOLATILE_CONST( fd_poh_returned_lock ) ) ) break;
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE();
    FD_VOLATILE( fd_poh_waiting_lock ) = 0UL;
  }
  FD_COMPILER_MFENCE();
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_poh_tile_t * ctx = (fd_poh_tile_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in.chunk0 || chunk>ctx->stake_in.wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in.chunk0, ctx->stake_in.wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in.mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;
  } else {
    if( FD_UNLIKELY( chunk<ctx->bank_in[ in_idx ].chunk0 || chunk>ctx->bank_in[ in_idx ].wmark || sz>USHORT_MAX ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->bank_in[ in_idx ].chunk0, ctx->bank_in[ in_idx ].wmark ));

    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->bank_in[ in_idx ].mem, chunk );

    fd_memcpy( ctx->_txns, src, sz-sizeof(fd_microblock_trailer_t) );
    ctx->_microblock_trailer = (fd_microblock_trailer_t*)(src+sz-sizeof(fd_microblock_trailer_t));
  }
}

static void
hash_transactions( void *       mem,
                   fd_txn_p_t * txns,
                   ulong        txn_cnt,
                   uchar *      mixin ) {
  fd_bmtree_commit_t * bmtree = fd_bmtree_commit_init( mem, 32UL, 1UL, 0UL );
  for( ulong i=0; i<txn_cnt; i++ ) {
    fd_txn_p_t * _txn = txns + i;
    if( FD_UNLIKELY( !(_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_txn_t * txn = TXN(_txn);
    for( ulong j=0; j<txn->signature_cnt; j++ ) {
      fd_bmtree_node_t node[1];
      fd_bmtree_hash_leaf( node, _txn->payload+txn->signature_off+64UL*j, 64UL, 1UL );
      fd_bmtree_commit_append( bmtree, node, 1UL );
    }
  }
  uchar * root = fd_bmtree_commit_fini( bmtree );
  fd_memcpy( mixin, root, 32UL );
}

static void
publish_microblock( fd_poh_tile_t *    ctx,
                    fd_mux_context_t * mux,
                    ulong              sig,
                    ulong              slot,
                    ulong              hashcnt_delta,
                    ulong              txn_cnt ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  meta->parent_offset = 1UL + slot - (ctx->reset_slot_hashcnt/ctx->hashcnt_per_slot);
  meta->reference_tick = (ctx->hashcnt/ctx->hashcnt_per_tick) % ctx->ticks_per_slot;
  meta->block_complete = !(ctx->hashcnt % ctx->hashcnt_per_slot);

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * header = (fd_entry_batch_header_t *)dst;
  header->hashcnt_delta = hashcnt_delta;
  fd_memcpy( header->hash, ctx->hash, 32UL );
  header->txn_cnt = txn_cnt;

  dst += sizeof(fd_entry_batch_header_t);
  ulong payload_sz = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)(ctx->_txns + i*sizeof(fd_txn_p_t));
    if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_memcpy( dst, txn->payload, txn->payload_sz );
    payload_sz += txn->payload_sz;
    dst += txn->payload_sz;
  }

  /* We always have credits to publish here, because we have a burst
     value of 3 credits, and at most we will publish_tick() once and
     then publish_became_leader() once, leaving one credit here to
     publish the microblock. */
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t)+payload_sz;
  fd_mux_publish( mux, sig, ctx->out_chunk, sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

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
  (void)in_idx;
  (void)seq;
  (void)opt_chunk;
  (void)opt_tsorig;

  fd_poh_tile_t * ctx = (fd_poh_tile_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    /* It might seem like we do not need to do state transitions in and
       out of being the leader here, since leader schedule updates are
       always one epoch in advance (whether we are leader or not would
       never change for the currently executing slot) but this is not
       true for new ledgers when the validator first boots.  We will
       likely be the leader in slot 1, and get notified of the leader
       schedule for that slot while we are still in it.

       For safety we just handle both transitions, in and out, although
       the only one possible should be into leader. */
    ulong next_leader_slot_hashcnt_after_frag = next_leader_slot_hashcnt( ctx );

    int currently_leader = ctx->hashcnt>=ctx->next_leader_slot_hashcnt;
    int leader_after_frag = ctx->hashcnt>=next_leader_slot_hashcnt_after_frag;

    FD_LOG_INFO(( "stake_update(before_leader=%lu,after_leader=%lu)",
                  ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot,
                  next_leader_slot_hashcnt_after_frag/ctx->hashcnt_per_slot ));

    ctx->next_leader_slot_hashcnt = next_leader_slot_hashcnt_after_frag;
    if( FD_UNLIKELY( currently_leader && !leader_after_frag ) ) no_longer_leader( ctx );

    /* Nothing to do if we transition into being leader, since it
       will just get picked up by the regular tick loop. */
    return;
  }

  ulong target_bank_idx = fd_disco_poh_sig_bank_tile( *opt_sig );
  ulong target_slot = fd_disco_poh_sig_slot( *opt_sig );

  ulong current_slot = ctx->hashcnt/ctx->hashcnt_per_slot;
  ulong leader_slot = ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot;
  if( FD_UNLIKELY( target_slot!=leader_slot || target_slot!=current_slot ) ) {
    fd_ext_bank_release_thunks( ctx->_microblock_trailer->load_and_execute_output );
    fd_ext_bank_release_pre_balance_info( ctx->_microblock_trailer->pre_balance_info );
    fd_fseq_update( ctx->pack_busy[ target_bank_idx ], ctx->_microblock_trailer->busy_seq );

    if     ( FD_LIKELY( target_slot<current_slot ) ) FD_MCNT_INC( POH_TILE, MICROBLOCK_TOO_EARLY, 1UL );
    else if( FD_LIKELY( target_slot>current_slot ) ) FD_MCNT_INC( POH_TILE, MICROBLOCK_TOO_LATE, 1UL );
    else                                             FD_MCNT_INC( POH_TILE, MICROBLOCK_NO_LONGER_LEADER, 1UL );
    FD_LOG_WARNING(( "packed too early or late for slot %lu", target_slot ));
    *opt_filter = 1;
    return;
  }

  if( FD_UNLIKELY( !ctx->current_leader_bank ) ) {
    /* Very unlikely if not impossible.  We became leader with a valid
       leader bank, and told pack to start packing.  Then at some point
       we got reset onto the same slot and lost the leader bank, so
       we cannot process the transactions anymore. */
    fd_ext_bank_release_thunks( ctx->_microblock_trailer->load_and_execute_output );
    fd_ext_bank_release_pre_balance_info( ctx->_microblock_trailer->pre_balance_info );
    fd_fseq_update( ctx->pack_busy[ target_bank_idx ], ctx->_microblock_trailer->busy_seq );

    FD_MCNT_INC( POH_TILE, NO_LEADER_BANK, 1UL );
    FD_LOG_WARNING(( "packed for a slot that doesn't have a leader bank anymore %lu", target_slot ));
    *opt_filter = 1;
    return;
  }

  ulong txn_cnt = (*opt_sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
  fd_txn_p_t * txns = (fd_txn_p_t *)(ctx->_txns);
  ulong sanitized_txn_cnt = 0UL;
  for( ulong i=0; i<txn_cnt; i++ ) { sanitized_txn_cnt += !!(txns[ i ].flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS); }

  uchar data[ 64 ];
  fd_memcpy( data, ctx->hash, 32UL );
  hash_transactions( ctx->bmtree, (fd_txn_p_t*)ctx->_txns, txn_cnt, data+32UL );
  fd_sha256_hash( data, 64UL, ctx->hash );

  ctx->hashcnt++;
  ulong hashcnt_delta = ctx->hashcnt - ctx->last_hashcnt;
  ctx->last_hashcnt = ctx->hashcnt;

  /* The hashing loop above will never leave us exactly one away from
     crossing a tick boundary, so this increment will never cause the
     current tick (or the slot) to change, except in low power mode
     for development, in which case we do need to register the tick
     with the leader bank.  We don't need to publish the tick since
     sending the microblock below is the publishing action. */
  if( FD_UNLIKELY( !(ctx->hashcnt%ctx->hashcnt_per_tick) ) ) {
    fd_ext_poh_register_tick( ctx->current_leader_bank, ctx->hash );
  }

  /* Commit must succeed so no failure path, since we have already
     updated the PoH hash to include these transactions.  This
     function takes ownership of the load_and_execute_output and
     pre_balance_info heap allocations and will free them before
     it returns.  They should not be reused. */
  fd_ext_bank_commit_txns( ctx->current_leader_bank, ctx->_microblock_trailer->abi_txns, sanitized_txn_cnt, ctx->_microblock_trailer->load_and_execute_output, ctx->_microblock_trailer->pre_balance_info );

  /* Indicate to pack tile we are done processing the transactions so it
     can pack new microblocks using these accounts.  DO NOT USE THE
     SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NOT LONGER VALID. */
  fd_fseq_update( ctx->pack_busy[ target_bank_idx ], ctx->_microblock_trailer->busy_seq );

  publish_microblock( ctx, mux, *opt_sig, target_slot, hashcnt_delta, txn_cnt );
}

void
fd_poh_join_privileged( void *                     shpoh,
                        fd_poh_tile_args_t const * args ) {
  FD_SCRATCH_ALLOC_INIT( l, shpoh );
  fd_poh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_tile_t ), sizeof( fd_poh_tile_t ) );

  if( FD_UNLIKELY( !strcmp( args->identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( args->identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_key.uc, identity_key, 32UL );
}

/* The Solana Labs client needs to communicate to the shred tile what
   the shred version is on boot, but shred tile does not live in the
   same address space, so have the PoH tile pass the value through
   via. a shared memory ulong. */

static volatile ulong * fd_shred_version;

void
fd_ext_shred_set_shred_version( ulong shred_version ) {
  while( FD_UNLIKELY( !fd_shred_version ) ) FD_SPIN_PAUSE();
  *fd_shred_version = shred_version;
}

/* Solana Labs also needs to write to some mcaches, so we trampoline
   that via. the PoH tile as well. */

struct poh_link {
  fd_frag_meta_t * mcache;
  ulong            depth;
  ulong            tx_seq;

  void *           mem;
  void *           dcache;
  ulong            chunk0;
  ulong            wmark;
  ulong            chunk;

  ulong            cr_avail;
  ulong            rx_cnt;
  ulong *          rx_fseqs[ 32UL ];
};

typedef struct poh_link poh_link_t;

poh_link_t gossip_pack;
poh_link_t stake_out;
poh_link_t crds_shred;

static void
poh_link_wait_credit( poh_link_t * link ) {
  if( FD_LIKELY( link->cr_avail ) ) return;

  while( 1 ) {
    ulong cr_query = ULONG_MAX;
    for( ulong i=0UL; i<link->rx_cnt; i++ ) {
      ulong const * _rx_seq = link->rx_fseqs[ i ];    
      ulong rx_seq = FD_VOLATILE_CONST( *_rx_seq );
      ulong rx_cr_query = (ulong)fd_long_max( (long)link->depth - fd_long_max( fd_seq_diff( link->tx_seq, rx_seq ), 0L ), 0L );
      cr_query = fd_ulong_min( rx_cr_query, cr_query );
    }
    if( FD_LIKELY( cr_query>0UL ) ) {
      link->cr_avail = cr_query;
      break;
    }
    FD_SPIN_PAUSE();
  }
}


static void
poh_link_publish( poh_link_t *  link,
                  ulong         sig,
                  uchar const * data,
                  ulong         data_len ) {
  while( FD_UNLIKELY( !FD_VOLATILE_CONST( link->mcache ) ) ) FD_SPIN_PAUSE();
  poh_link_wait_credit( link );

  uchar * dst = (uchar *)fd_chunk_to_laddr( link->mem, link->chunk );
  fd_memcpy( dst, data, data_len );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( link->mcache, link->depth, link->tx_seq, sig, link->chunk, data_len, 0UL, 0UL, tspub );
  link->chunk = fd_dcache_compact_next( link->chunk, data_len, link->chunk0, link->wmark );
  link->cr_avail--;
  link->tx_seq++;
}

static void
poh_link_init( poh_link_t *                   link,
               fd_poh_tile_topo_out_t const * topo ) {

  link->mem      = topo->wksp;
  link->depth    = fd_mcache_depth( topo->mcache );
  link->tx_seq   = 0UL;
  link->dcache   = topo->dcache;
  link->chunk0   = fd_dcache_compact_chunk0( topo->wksp, topo->dcache );
  link->wmark    = fd_dcache_compact_wmark ( topo->wksp, topo->dcache, topo->mtu );
  link->chunk    = link->chunk0;
  link->cr_avail = 0UL;
  link->rx_cnt   = topo->rx_cnt;
  FD_TEST( topo->rx_cnt<=32UL );
  for( ulong i=0UL; i<topo->rx_cnt; i++ ) {
    link->rx_fseqs[ i ] = topo->rx_fseq[ i ];
  }
  FD_COMPILER_MFENCE();
  link->mcache = topo->mcache;
  FD_COMPILER_MFENCE();
  FD_TEST( link->mcache );
}

void
fd_ext_poh_publish_gossip_vote( uchar * data,
                                ulong   data_len ) {
  poh_link_publish( &gossip_pack, 0UL, data, data_len );
}

void
fd_ext_poh_publish_leader_schedule( uchar * data,
                                    ulong   data_len ) {
  poh_link_publish( &stake_out, 2UL, data, data_len );
}

void
fd_ext_poh_publish_cluster_info( uchar * data,
                                 ulong   data_len ) {
  poh_link_publish( &crds_shred, 2UL, data, data_len );
}

fd_poh_tile_t *
fd_poh_tile_join( void *                     shpoh,
                  fd_poh_tile_args_t const * args,
                  fd_poh_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shpoh );
  fd_poh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_tile_t ), sizeof( fd_poh_tile_t ) );
  void * stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * sha256   = FD_SCRATCH_ALLOC_APPEND( l, FD_SHA256_ALIGN,                  FD_SHA256_FOOTPRINT                );
  void * bmtree   = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN,           FD_BMTREE_COMMIT_FOOTPRINT(0)      );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->stake_ci = NONNULL( fd_stake_ci_join( fd_stake_ci_new( stake_ci, &ctx->identity_key ) ) );
  ctx->sha256 = NONNULL( fd_sha256_join( fd_sha256_new( sha256 ) ) );
  ctx->bmtree = NONNULL( bmtree );
  ctx->current_leader_bank = NULL;
  ctx->signal_leader_change = NULL;

  ctx->hashcnt = 0UL;
  ctx->last_hashcnt = 0UL;
  ctx->next_leader_slot_hashcnt = ULONG_MAX;
  ctx->send_leader_now_for_slot = ULONG_MAX;
  ctx->reset_slot_hashcnt = ULONG_MAX;

  poh_link_init( &gossip_pack, &topo->gossip_pack_out );
  poh_link_init( &stake_out,   &topo->stake_out       );
  poh_link_init( &crds_shred,  &topo->crds_shred_out  );

  FD_LOG_NOTICE(( "PoH waiting to be initialized by Solana Labs client... %lu %lu", fd_poh_waiting_lock, fd_poh_returned_lock ));
  FD_VOLATILE( fd_poh_global_ctx ) = ctx;
  FD_COMPILER_MFENCE();
  for(;;) {
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_poh_waiting_lock ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_VOLATILE( fd_poh_waiting_lock ) = 0UL;
  FD_VOLATILE( fd_poh_returned_lock ) = 1UL;
  FD_COMPILER_MFENCE();
  for(;;) {
    if( FD_UNLIKELY( !FD_VOLATILE_CONST( fd_poh_returned_lock ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( ctx->reset_slot_hashcnt==ULONG_MAX ) ) FD_LOG_ERR(( "PoH was not initialized by Solana Labs client" ));

  ctx->bank_cnt = topo->bank_in_cnt;
  for( ulong i=0UL; i<topo->bank_in_cnt; i++ ) {
    ctx->bank_in[ i ].mem    = topo->bank_in_wksp[ i ];
    ctx->bank_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->bank_in[ i ].mem, topo->bank_in_dcache[ i ] );
    ctx->bank_in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->bank_in[ i ].mem, topo->bank_in_dcache[ i ], topo->bank_in_mtu[ i ] );

    ctx->pack_busy[ i ] = topo->pack_busy[ i ];
    if( FD_UNLIKELY( !ctx->pack_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
  }

  fd_shred_version = topo->shred_version;
  FD_TEST( fd_shred_version );

  ctx->stake_in_idx    = topo->stake_in_idx;
  ctx->stake_in.mem    = topo->stake_in_wksp;
  ctx->stake_in.chunk0 = fd_dcache_compact_chunk0( ctx->stake_in.mem, topo->stake_in_dcache );
  ctx->stake_in.wmark  = fd_dcache_compact_wmark ( ctx->stake_in.mem, topo->stake_in_dcache, topo->stake_in_mtu );

  ctx->out_mem    = topo->primary_out_wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->primary_out_dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->primary_out_dcache, topo->primary_out_mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shpoh + fd_poh_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shpoh - fd_poh_tile_footprint( args ), scratch_top, (ulong)shpoh + fd_poh_tile_footprint( args ) ));

  return ctx;
}

void
fd_poh_tile_run( fd_poh_tile_t *         ctx,
                 fd_cnc_t *              cnc,
                 ulong                   in_cnt,
                 fd_frag_meta_t const ** in_mcache,
                 ulong **                in_fseq,
                 fd_frag_meta_t *        mcache,
                 ulong                   out_cnt,
                 ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_housekeeping = during_housekeeping,
    .after_credit        = after_credit,
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               3UL, /* One tick, one microblock, and one leader update. */
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
