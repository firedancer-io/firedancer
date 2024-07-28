#include "fd_poh_tile.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

ulong
fd_poh_tile_align( void ) {
  return 128UL;
}

ulong
fd_poh_tile_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_poh_tile_ctx_t ), sizeof( fd_poh_tile_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, FD_SHA256_ALIGN, FD_SHA256_FOOTPRINT );
  return FD_LAYOUT_FINI( l, fd_poh_tile_align() );
}

void
fd_poh_tile_initialize( fd_poh_tile_ctx_t * ctx,
                        ulong               tick_duration_ns, /* See clock comments above, will be 500ns for mainnet-beta. */
                        ulong               hashcnt_per_tick,    /* See clock comments above, will be 12,500 for mainnet-beta. */
                        ulong               ticks_per_slot,      /* See clock comments above, will almost always be 64. */
                        ulong               tick_height,         /* The counter (height) of the tick to start hashing on top of. */
                        uchar const *       last_entry_hash      /* Points to start of a 32 byte region of memory, the hash itself at the tick height. */ ) {
  FD_LOG_WARNING(( "tick_duration_ns: %lu",tick_duration_ns ));
  ctx->slot                = tick_height/ticks_per_slot;
  ctx->hashcnt             = 0UL;
  ctx->last_slot           = ctx->slot;
  ctx->last_hashcnt        = 0UL;
  ctx->reset_slot          = ctx->slot;
  ctx->reset_slot_start_ns = fd_log_wallclock(); /* safe to call from Rust */

  memcpy( ctx->hash, last_entry_hash, 32UL );

  /* Static configuration about the clock. */
  ctx->tick_duration_ns = tick_duration_ns;
  ctx->hashcnt_per_tick = hashcnt_per_tick;
  ctx->ticks_per_slot   = ticks_per_slot;

  /* Recompute derived information about the clock. */
  ctx->slot_duration_ns    = (double)ticks_per_slot*(double)tick_duration_ns;
  ctx->hashcnt_duration_ns = (double)tick_duration_ns/(double)hashcnt_per_tick;
  ctx->hashcnt_per_slot    = ticks_per_slot*hashcnt_per_tick;

  /* Can be derived from other information, but we precompute it
     since it is used frequently. */
  ctx->hashcnt_per_slot = ticks_per_slot*hashcnt_per_tick;

  if( FD_UNLIKELY( ctx->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    ctx->max_microblocks_per_slot = ctx->ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    ctx->max_microblocks_per_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ctx->ticks_per_slot*(ctx->hashcnt_per_tick-1UL) );
  }
}

/* fd_poh_tile_reached_leader_slot returns 1 if we have reached a slot
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
fd_poh_tile_reached_leader_slot( fd_poh_tile_ctx_t * ctx,
                                 ulong *             out_leader_slot,
                                 ulong *             out_reset_slot ) {
  *out_leader_slot = ctx->next_leader_slot;
  *out_reset_slot  = ctx->reset_slot;

  if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ||
                   ctx->slot<ctx->next_leader_slot ) ) {
    /* Didn't reach our leader slot yet. */
    return 0;
  }

  if( FD_LIKELY( ctx->reset_slot==ctx->next_leader_slot ) ) {
    /* We were reset onto our leader slot, because the prior leader
       completed theirs, so we should start immediately, no need for a
       grace period. */
    return 1;
  }

  // if( FD_LIKELY( ctx->next_leader_slot>=1UL ) ) {
  //   fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, ctx->next_leader_slot-1UL ); /* Safe to call from Rust */
  //   if( FD_LIKELY( leaders ) ) {
  //     fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, ctx->next_leader_slot-1UL ); /* Safe to call from Rust */
  //     if( FD_LIKELY( leader ) ) {
  //       if( FD_UNLIKELY( !memcmp( leader->uc, ctx->identity_key.uc, 32UL ) ) ) {
  //         /* We were the leader in the previous slot, so also no need for
  //           a grace period.  We wouldn't get here if we were still
  //           processing the prior slot so begin new one immediately. */
  //         return 1;
  //       }
  //     }
  //   }
  // }

  if( FD_UNLIKELY( ctx->next_leader_slot-ctx->reset_slot>=4UL ) ) {
    /* The prior leader has not completed any slot successfully during
       their 4 leader slots, so they are probably inactive and no need
       to give a grace period. */
    return 1;
  }

  if( FD_LIKELY( ctx->slot-ctx->next_leader_slot<GRACE_SLOTS ) ) {
    /*  The prior leader hasn't finished their last slot, and they are
        likely still publishing, and within their grace period of two
        slots so we will keep waiting. */
    return 0;
  }

  return 1;
}

void
fd_poh_tile_publish_became_leader( fd_poh_tile_ctx_t * ctx,
                                   void const *        current_leader_data,
                                   ulong               slot ) {
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  fd_histf_sample( ctx->begin_leader_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );

  long slot_start_ns = ctx->reset_slot_start_ns + (long)((double)(slot-ctx->reset_slot)*ctx->slot_duration_ns);

  /* No need to check flow control, there are always credits became when we
     are leader, we will not "become" leader again until we are done, so at
     most one frag in flight at a time. */

  uchar * dst = ctx->get_pack_buffer_func( ctx->arg );

  fd_became_leader_t * leader = (fd_became_leader_t *)dst;
  leader->slot_start_ns           = slot_start_ns;
  leader->slot_end_ns             = (long)((double)slot_start_ns + ctx->slot_duration_ns);
  leader->bank                    = current_leader_data;
  leader->max_microblocks_in_slot = ctx->max_microblocks_per_slot;
  leader->ticks_per_slot          = ctx->ticks_per_slot;
  leader->total_skipped_ticks     = ctx->ticks_per_slot*(slot-ctx->reset_slot);

  if( FD_UNLIKELY( leader->ticks_per_slot+leader->total_skipped_ticks>=MAX_SKIPPED_TICKS ) )
    FD_LOG_ERR(( "Too many skipped ticks %lu for slot %lu, chain must halt", leader->ticks_per_slot+leader->total_skipped_ticks, slot ));

  FD_LOG_INFO(( "became_leader(slot=%lu)", slot ));
  
  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_BECAME_LEADER, 0UL );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ctx->publish_pack_func( ctx->arg, tspub, sig, sizeof(fd_became_leader_t) );
}

/* The PoH tile knows when it should become leader by waiting for its
   leader slot (with the operating system clock).  This function is so
   that when it becomes the leader, it can be told what the leader bank
   is by the replay stage.  See the notes in the long comment above for
   more on how this works. */

void
fd_poh_tile_begin_leader( fd_poh_tile_ctx_t * ctx,
                          ulong               slot,
                          ulong               hashcnt_per_tick ) {
  FD_TEST( ctx->current_leader_slot == FD_SLOT_NULL );

  if( FD_UNLIKELY( slot!=ctx->slot ) ) FD_LOG_ERR(( "Trying to begin leader slot %lu but we are now on slot %lu", slot, ctx->slot ));
  if( FD_UNLIKELY( slot!=ctx->next_leader_slot ) ) FD_LOG_ERR(( "Trying to begin leader slot %lu but we are now on slot %lu", slot, ctx->next_leader_slot ));

  if( FD_UNLIKELY( ctx->hashcnt_per_tick!=hashcnt_per_tick ) ) {
    FD_LOG_WARNING(( "hashes per tick changed from %lu to %lu", ctx->hashcnt_per_tick, hashcnt_per_tick ));

    /* Recompute derived information about the clock. */
    ctx->hashcnt_duration_ns = (double)ctx->tick_duration_ns/(double)hashcnt_per_tick;
    ctx->hashcnt_per_slot = ctx->ticks_per_slot*hashcnt_per_tick;
    ctx->hashcnt_per_tick = hashcnt_per_tick;

    if( FD_UNLIKELY( ctx->hashcnt_per_tick==1UL ) ) {
      /* Low power producer, maximum of one microblock per tick in the slot */
      ctx->max_microblocks_per_slot = ctx->ticks_per_slot;
    } else {
      /* See the long comment in after_credit for this limit */
      ctx->max_microblocks_per_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ctx->ticks_per_slot*(ctx->hashcnt_per_tick-1UL) );
    }

    /* Discard any ticks we might have done in the interim.  They will
       have the wrong number of hashes per tick.  We can just catch back
       up quickly if not too many slots were skipped and hopefully
       publish on time.  Note that tick production and verification of
       skipped slots is done for the eventual bank that publishes a
       slot, for example:

        Reset Slot:            998
        Epoch Transition Slot: 1000
        Leader Slot:           1002

       In this case, if a feature changing the hashcnt_per_tick is
       activated in slot 1000, and we are publishing empty ticks for
       slots 998, 999, 1000, and 1001, they should all have the new
       hashes_per_tick number of hashes, rather than the older one, or
       some combination. */

    FD_TEST( ctx->last_slot==ctx->reset_slot );
    FD_TEST( !ctx->last_hashcnt );
    ctx->slot = ctx->reset_slot;
    ctx->hashcnt = 0UL;
  }

  ctx->current_leader_slot     = slot;
  ctx->microblocks_lower_bound = 0UL;

  /* We are about to start publishing to the shred tile for this slot
    so update the highwater mark so we never republish in this slot
    again.  Also check that the leader slot is greater than the
    highwater, which should have been ensured earlier. */

  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || slot>=ctx->highwater_leader_slot );
  ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), slot );

  fd_poh_tile_publish_became_leader( ctx, (void *)(ctx->reset_slot-1UL), slot );
}

/* Determine what the next slot is in the leader schedule is that we are
   leader.  Includes the current slot.  If we are not leader in what
   remains of the current and next epoch, return ULONG_MAX. */

ulong
fd_poh_tile_next_leader_slot( fd_poh_tile_ctx_t * ctx ) {
  /* If we have published anything in a particular slot, then we
     should never become leader for that slot again. */
  ulong min_leader_slot = fd_ulong_max( ctx->slot, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ) );

  for(;;) {
    fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, min_leader_slot ); /* Safe to call from Rust */
    if( FD_UNLIKELY( !leaders ) ) break;

    while( min_leader_slot<(leaders->slot0+leaders->slot_cnt) ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, min_leader_slot ); /* Safe to call from Rust */
      if( FD_UNLIKELY( !memcmp( leader->key, ctx->identity_key.key, 32UL ) ) ) return min_leader_slot;
      min_leader_slot++;
    }
  }

  return ULONG_MAX;
}

void
fd_poh_tile_no_longer_leader( fd_poh_tile_ctx_t * ctx ) {
  /* If we stop being leader in a slot, we can never become leader in
    that slot again, and all in-flight microblocks for that slot
    should be dropped. */
  ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), ctx->slot );
  ctx->current_leader_slot = FD_SLOT_NULL;
  ctx->next_leader_slot = fd_poh_tile_next_leader_slot( ctx );

  FD_COMPILER_MFENCE();
  ctx->signal_leader_change_func( ctx->arg );
  FD_LOG_INFO(( "fd_poh_tile_no_longer_leader(next_leader_slot=%lu)", ctx->next_leader_slot ));
}

void
fd_poh_tile_reset( fd_poh_tile_ctx_t * ctx,
                   ulong               completed_bank_slot, /* The slot that successfully produced a block */
                   uchar const *       reset_blockhash,     /* The hash of the last tick in the produced block */
                   ulong               hashcnt_per_tick     /* The hashcnt per tick of the bank that completed */) {
  int leader_before_reset = ctx->slot>=ctx->next_leader_slot;
  if( FD_UNLIKELY( leader_before_reset && ctx->current_leader_slot!=FD_SLOT_NULL ) ) {
  /* If we were in the middle of a leader slot that we notified pack
       pack to start packing for we can never publish into that slot
       again, mark all in-flight microblocks to be dropped. */
    ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), 1UL+ctx->slot );
  }

  if( FD_UNLIKELY( ctx->expect_sequential_leader_slot==(completed_bank_slot+1UL) ) ) {
    /* If we are being reset onto a slot, it means some block was fully
      processed, so we reset to build on top of it.  Typically we want
      to update the reset_slot_start_ns to the current time, because
      the network will give the next leader 400ms to publish,
      regardless of how long the prior leader took.

      But: if we were leader in the prior slot, and the block was our
      own we can do better.  We know that the next slot should start
      exactly 400ms after the prior one started, so we can use that as
      the reset slot start time instead. */
    ctx->reset_slot_start_ns = ctx->reset_slot_start_ns + (long)((double)((completed_bank_slot+1UL)-ctx->reset_slot)*ctx->slot_duration_ns);
  } else {
    ctx->reset_slot_start_ns = fd_log_wallclock(); /* safe to call from Rust */
  }
  ctx->expect_sequential_leader_slot = ULONG_MAX;  

  memcpy( ctx->hash, reset_blockhash, 32UL );
  ctx->slot         = completed_bank_slot+1UL;
  ctx->hashcnt      = 0UL;
  ctx->last_slot    = ctx->slot;
  ctx->last_hashcnt = 0UL;
  ctx->reset_slot   = ctx->slot;

  if( FD_UNLIKELY( ctx->hashcnt_per_tick!=hashcnt_per_tick ) ) {
    FD_LOG_WARNING(( "hashes per tick changed from %lu to %lu", ctx->hashcnt_per_tick, hashcnt_per_tick ));

    /* Recompute derived information about the clock. */
    ctx->hashcnt_duration_ns = (double)ctx->tick_duration_ns/(double)hashcnt_per_tick;
    ctx->hashcnt_per_slot = ctx->ticks_per_slot*hashcnt_per_tick;
    ctx->hashcnt_per_tick = hashcnt_per_tick;

    if( FD_UNLIKELY( ctx->hashcnt_per_tick==1UL ) ) {
      /* Low power producer, maximum of one microblock per tick in the slot */
      ctx->max_microblocks_per_slot = ctx->ticks_per_slot;
    } else {
      /* See the long comment in after_credit for this limit */
      ctx->max_microblocks_per_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ctx->ticks_per_slot*(ctx->hashcnt_per_tick-1UL) );
    }
  }

  if( FD_UNLIKELY( leader_before_reset ) ) {
    /* No longer have a leader bank if we are reset. Replay stage will
       call back again to give us a new one if we should become leader
       for the reset slot.

       The order is important here, ctx->hashcnt must be updated before
       calling no_longer_leader. */
    fd_poh_tile_no_longer_leader( ctx );
  }
  ctx->next_leader_slot = fd_poh_tile_next_leader_slot( ctx );
  FD_LOG_INFO(( "fd_poh_tile_reset(slot=%lu,next_leader_slot=%lu) slots_until_leader=%lu", ctx->reset_slot, ctx->next_leader_slot, ctx->next_leader_slot-ctx->reset_slot ));
}

int
fd_poh_tile_get_leader_after_n_slots( fd_poh_tile_ctx_t * ctx,
                                      ulong               n,
                                      uchar               out_pubkey[ static 32 ] ) {
  ulong slot = ctx->slot + n;
  fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, slot ); /* Safe to call from Rust */

  int copied = 0;
  if( FD_LIKELY( leaders ) ) {
    fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, slot ); /* Safe to call from Rust */
    if( FD_LIKELY( leader ) ) {
      memcpy( out_pubkey, leader, 32UL );
      copied = 1;
    }
  }
  return copied;
}

void
fd_poh_tile_publish_tick( fd_poh_tile_ctx_t * ctx,
                          uchar               hash[ static 32 ],
                          int                 is_skipped ) {
  ulong hashcnt = ctx->hashcnt_per_tick*(1UL+(ctx->last_hashcnt/ctx->hashcnt_per_tick));

  uchar * dst = ctx->get_microblock_buffer_func( ctx->arg );

  FD_TEST( ctx->last_slot>=ctx->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  if( is_skipped ) {
    meta->reference_tick = 0UL;
    meta->block_complete = 0;
  } else {
    meta->reference_tick = hashcnt/ctx->hashcnt_per_tick;
    meta->block_complete = hashcnt==ctx->hashcnt_per_slot;
  }
  ulong slot = fd_ulong_if( meta->block_complete, ctx->slot-1UL, ctx->slot );
  meta->parent_offset = 1UL+slot-ctx->reset_slot;

  FD_TEST( hashcnt>ctx->last_hashcnt );
  ulong hash_delta = hashcnt-ctx->last_hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * tick = (fd_entry_batch_header_t *)dst;
  tick->hashcnt_delta = hash_delta;
  fd_memcpy( tick->hash, hash, 32UL );
  tick->txn_cnt = 0UL;

  FD_LOG_WARNING(("PUB TICK(%d): %lu %lu %lu %lu", is_skipped, slot, hash_delta, hashcnt, ctx->hashcnt_per_slot ));
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t);
  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  ctx->publish_microblock_func( ctx->arg, tspub, sig, sz );

  if( FD_UNLIKELY( hashcnt==ctx->hashcnt_per_slot ) ) {
    ctx->last_slot++;
    ctx->last_hashcnt = 0UL;
  } else {
    ctx->last_hashcnt = hashcnt;
  }
}

void
fd_poh_tile_after_credit( fd_poh_tile_ctx_t * ctx,
                          int *               opt_poll_in ) {
  int is_leader = ctx->next_leader_slot!=ULONG_MAX && ctx->slot>=ctx->next_leader_slot;
  if( FD_UNLIKELY( is_leader && ctx->current_leader_slot==FD_SLOT_NULL ) ) {
    /* If we are the leader, but we didn't yet learn what the leader
       bank object is from the replay stage, do not do any hashing.

       This is not ideal, but greatly simplifies the control flow. */
    return;
  }

  /* If we have skipped ticks pending because we skipped some slots to
     become leader, register them now one at a time. */
  if( FD_UNLIKELY( is_leader && ctx->last_slot<ctx->slot ) ) {
    ulong publish_hashcnt = ctx->last_hashcnt+ctx->hashcnt_per_tick;
    ulong tick_idx = (ctx->last_slot*ctx->ticks_per_slot+publish_hashcnt/ctx->hashcnt_per_tick)%MAX_SKIPPED_TICKS;

    ctx->register_tick_func( ctx->arg, ctx->current_leader_slot, ctx->skipped_tick_hashes[ tick_idx ] );
    fd_poh_tile_publish_tick( ctx, ctx->skipped_tick_hashes[ tick_idx ], 1 );

    /* If we are catching up now and publishing a bunch of skipped
       ticks, we do not want to process any incoming microblocks until
       all the skipped ticks have been published out; otherwise we would
       intersperse skipped tick messages with microblocks. */
    *opt_poll_in = 0;
    return;
  }


  int low_power_mode = ctx->hashcnt_per_tick==1UL;

  /* If we are the leader, always leave enough capacity in the slot so
     that we can mixin any potential microblocks still coming from the
     pack tile for this slot. */
  ulong max_remaining_microblocks = ctx->max_microblocks_per_slot - ctx->microblocks_lower_bound;
  /* With hashcnt_per_tick hashes per tick, we actually get
     hashcnt_per_tick-1 chances to mixin a microblock.  For each tick
     span that we need to reserve, we also need to reserve the hashcnt
     for the tick, hence the +
     max_remaining_microblocks/(hashcnt_per_tick-1) rounded up.

     However, if hashcnt_per_tick is 1 because we're in low power mode,
     this should probably just be max_remaining_microblocks. */
  ulong max_remaining_ticks_or_microblocks = max_remaining_microblocks;
  if( FD_LIKELY( !low_power_mode ) ) max_remaining_ticks_or_microblocks += (max_remaining_microblocks+ctx->hashcnt_per_tick-2UL)/(ctx->hashcnt_per_tick-1UL);

  ulong restricted_hashcnt = fd_ulong_if( ctx->hashcnt_per_slot>=max_remaining_ticks_or_microblocks, ctx->hashcnt_per_slot-max_remaining_ticks_or_microblocks, 0UL );

  ulong min_hashcnt = ctx->hashcnt;

  if( FD_LIKELY( !low_power_mode ) ) {
    /* Recall that there are two kinds of events that will get published
       to the shredder,

         (a) Ticks. These occur every 62,500 (hashcnt_per_tick) hashcnts,
             and there will be 64 (ticks_per_slot) of them in each slot.

             Ticks must not have any transactions mixed into the hash.
             This is not strictly needed in theory, but is required by the
             current consensus protocol.  They get published here in
             after_credit.

         (b) Microblocks.  These can occur at any other hashcnt, as long
             as it is not a tick.  Microblocks cannot be empty, and must
             have at least one transactions mixed in.  These get
             published in after_frag.

       If hashcnt_per_tick is 1, then we are in low power mode and the
       following does not apply, since we can mix in transactions at any
       time.

       In the normal, non-low-power mode, though, we have to be careful
       to make sure that we do not publish microblocks on tick
       boundaries.  To do that, we need to obey two rules:
         (i)  after_credit must not leave hashcnt one before a tick
              boundary
         (ii) if after_credit begins one before a tick boundary, it must
              advance hashcnt and publish the tick

       There's some interplay between min_hashcnt and restricted_hashcnt
       here, and we need to show that there's always a value of
       target_hashcnt we can pick such that
           min_hashcnt <= target_hashcnt <= restricted_hashcnt.
       We'll prove this by induction for current_slot==0 and
       is_leader==true, since all other slots should be the same.

       Let m_j and r_j be the min_hashcnt and restricted_hashcnt
       (respectively) for the jth call to after_credit in a slot.  We
       want to show that for all values of j, it's possible to pick a
       value h_j, the value of target_hashcnt for the jth call to
       after_credit (which is also the value of hashcnt after
       after_credit has completed) such that m_j<=h_j<=r_j.

       Additionally, let T be hashcnt_per_tick and N be ticks_per_slot.

       Starting with the base case, j==0.  m_j=0, and
         r_0 = N*T - max_microblocks_per_slot
                   - ceil(max_microblocks_per_slot/(T-1)).

       This is monotonic decreasing in max_microblocks_per_slot, so it
       achieves its minimum when max_microblocks_per_slot is its
       maximum.
           r_0 >= N*T - N*(T-1) - ceil( (N*(T-1))/(T-1))
                = N*T - N*(T-1)-N = 0.
       Thus, m_0 <= r_0, as desired.



       Then, for the inductive step, assume there exists h_j such that
       m_j<=h_j<=r_j, and we want to show that there exists h_{j+1},
       which is the same as showing m_{j+1}<=r_{j+1}.

       Let a_j be 1 if we had a microblock immediately following the jth
       call to after_credit, and 0 otherwise.  Then hashcnt at the start
       of the (j+1)th call to after_frag is h_j+a_j.
       Also, set b_{j+1}=1 if we are in the case covered by rule (ii)
       above during the (j+1)th call to after_credit, i.e. if
       (h_j+a_j)%T==T-1.  Thus, m_{j+1} = h_j + a_j + b_{j+1}.

       If we received an additional microblock, then
       max_remaining_microblocks goes down by 1, and
       max_remaining_ticks_or_microblocks goes down by either 1 or 2,
       which means restricted_hashcnt goes up by either 1 or 2.  In
       particular, it goes up by 2 if the new value of
       max_remaining_microblocks (at the start of the (j+1)th call to
       after_credit) is congruent to 0 mod T-1.  Let b'_{j+1} be 1 if
       this condition is met and 0 otherwise.  If we receive a
       done_packing message, restricted_hashcnt can go up by more, but
       we can ignore that case, since it is less restrictive.
       Thus, r_{j+1}=r_j+a_j+b'_{j+1}.

       If h_j < r_j (strictly less), then h_j+a_j < r_j+a_j.  And thus,
       since b_{j+1}<=b'_{j+1}+1, just by virtue of them both being
       binary,
             h_j + a_j + b_{j+1} <  r_j + a_j + b'_{j+1} + 1,
       which is the same (for integers) as
             h_j + a_j + b_{j+1} <= r_j + a_j + b'_{j+1},
                 m_{j+1}         <= r_{j+1}

       On the other hand, if h_j==r_j, this is easy unless b_{j+1}==1,
       which can also only happen if a_j==1.  Then (h_j+a_j)%T==T-1,
       which means there's an integer k such that

             h_j+a_j==(ticks_per_slot-k)*T-1
             h_j    ==ticks_per_slot*T -  k*(T-1)-1  - k-1
                    ==ticks_per_slot*T - (k*(T-1)+1) - ceil( (k*(T-1)+1)/(T-1) )

       Since h_j==r_j in this case, and
       r_j==(ticks_per_slot*T) - max_remaining_microblocks_j - ceil(max_remaining_microblocks_j/(T-1)),
       we can see that the value of max_remaining_microblocks at the
       start of the jth call to after_credit is k*(T-1)+1.  Again, since
       a_j==1, then the value of max_remaining_microblocks at the start
       of the j+1th call to after_credit decreases by 1 to k*(T-1),
       which means b'_{j+1}=1.

       Thus, h_j + a_j + b_{j+1} == r_j + a_j + b'_{j+1}, so, in
       particular, h_{j+1}<=r_{j+1} as desired. */
     min_hashcnt += (ulong)(min_hashcnt%ctx->hashcnt_per_tick == (ctx->hashcnt_per_tick-1UL)); /* add b_{j+1}, enforcing rule (ii) */
  }
  /* Now figure out how many hashes are needed to "catch up" the hash
     count to the current system clock, and clamp it to the allowed
     range. */
  long now = fd_log_wallclock();
  ulong target_hashcnt = (ulong)((double)(now - ctx->reset_slot_start_ns) / ctx->hashcnt_duration_ns) - (ctx->slot-ctx->reset_slot)*ctx->hashcnt_per_slot;
  /* Clamp to [min_hashcnt, restricted_hashcnt] as above */
  target_hashcnt = fd_ulong_max( fd_ulong_min( target_hashcnt, restricted_hashcnt ), min_hashcnt );

  /* The above proof showed that it was always possible to pick a value
     of target_hashcnt, but we still have a lot of freedom in how to
     pick it.  It simplifies the code a lot if we don't keep going after
     a tick in this function.  In particular, we want to publish at most
     1 tick in this call, since otherwise we could consume infinite
     credits to publish here.  The credits are set so that we should
     only ever publish one tick during this loop.  Also, all the extra
     stuff (leader transitions, publishing ticks, etc.) we have to do
     happens at tick boundaries, so this lets us consolidate all those
     cases.

     Mathematically, since the current value of hashcnt is h_j+a_j, the
     next tick (advancing a full tick if we're currently at a tick) is
     t_{j+1} = T*(floor( (h_j+a_j)/T )+1).  We need to show that if we set
     h'_{j+1} = min( h_{j+1}, t_{j+1} ), it is still valid.

     First, h'_{j+1} <= h_{j+1} <= r_{j+1}, so we're okay in that
     direction.

     Next, observe that t_{j+1}>=h_j + a_j + 1, and recall that b_{j+1}
     is 0 or 1. So then,
                    t_{j+1} >= h_j+a_j+b_{j+1} = m_{j+1}.

     We know h_{j+1) >= m_{j+1} from before, so then h'_{j+1} >=
     m_{j+1}, as desired. */

  ulong next_tick_hashcnt = ctx->hashcnt_per_tick * (1UL+(ctx->hashcnt/ctx->hashcnt_per_tick));
  target_hashcnt = fd_ulong_min( target_hashcnt, next_tick_hashcnt );

  /* We still need to enforce rule (i). We know that min_hashcnt%T !=
     T-1 because of rule (ii).  That means that if target_hashcnt%T ==
     T-1 at this point, target_hashcnt > min_hashcnt (notice the
     strict), so target_hashcnt-1 >= min_hashcnt and is thus still a
     valid choice for target_hashcnt. */
  target_hashcnt -= (ulong)( (!low_power_mode) & ((target_hashcnt%ctx->hashcnt_per_tick)==(ctx->hashcnt_per_tick-1UL)) );

  FD_TEST( target_hashcnt >= ctx->hashcnt       );
  FD_TEST( target_hashcnt >= min_hashcnt        );
  FD_TEST( target_hashcnt <= restricted_hashcnt );

  if( FD_UNLIKELY( ctx->hashcnt==target_hashcnt ) ) return; /* Nothing to do, don't publish a tick twice */

  while( ctx->hashcnt<target_hashcnt ) {
    fd_sha256_hash( ctx->hash, 32UL, ctx->hash );
    ctx->hashcnt++;
  }

  if( FD_UNLIKELY( ctx->hashcnt==ctx->hashcnt_per_slot ) ) {
    ctx->slot++;
    ctx->hashcnt = 0UL;
  }

  if( FD_UNLIKELY( !is_leader && !(ctx->hashcnt%ctx->hashcnt_per_tick ) ) ) {
    /* We finished a tick while not leader... save the current hash so
       it can be played back into the bank when we become the leader. */
    ulong tick_idx = (ctx->slot*ctx->ticks_per_slot+ctx->hashcnt/ctx->hashcnt_per_tick)%MAX_SKIPPED_TICKS;
    fd_memcpy( ctx->skipped_tick_hashes[ tick_idx ], ctx->hash, 32UL );

    ulong initial_tick_idx = (ctx->last_slot*ctx->ticks_per_slot+ctx->last_hashcnt/ctx->hashcnt_per_tick)%MAX_SKIPPED_TICKS;
    if( FD_UNLIKELY( tick_idx==initial_tick_idx ) ) FD_LOG_ERR(( "Too many skipped ticks from slot %lu to slot %lu, chain must halt", ctx->last_slot, ctx->slot ));
  }

  if( FD_UNLIKELY( is_leader && !(ctx->hashcnt%ctx->hashcnt_per_tick) ) ) {
    /* We ticked while leader... tell the leader bank. */
    ctx->register_tick_func( ctx->arg, ctx->current_leader_slot, ctx->hash );
    FD_LOG_WARNING(("TICK TIME"));
    /* And send an empty microblock (a tick) to the shred tile. */
    fd_poh_tile_publish_tick( ctx, ctx->hash, 0 );
  }

  if( FD_UNLIKELY( is_leader && ctx->slot>ctx->next_leader_slot ) ) {
    /* We ticked while leader and are no longer leader... transition
       the state machine. */
    FD_TEST( !max_remaining_microblocks );
    fd_poh_tile_no_longer_leader( ctx );
    ctx->expect_sequential_leader_slot = ctx->slot;

    double tick_per_ns = fd_tempo_tick_per_ns( NULL );
    fd_histf_sample( ctx->slot_done_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );
  }
}

void
fd_poh_tile_init_stakes( fd_poh_tile_ctx_t * ctx, uchar const * stakes_msg ) {
  fd_stake_ci_stake_msg_init( ctx->stake_ci, stakes_msg );
}

void
fd_poh_tile_fini_stakes( fd_poh_tile_ctx_t * ctx ) {
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
    ulong next_leader_slot_after_frag = fd_poh_tile_next_leader_slot( ctx );

    int currently_leader  = ctx->slot>=ctx->next_leader_slot;
    int leader_after_frag = ctx->slot>=next_leader_slot_after_frag;

    FD_LOG_INFO(( "stake_update(before_leader=%lu,after_leader=%lu)",
                  ctx->next_leader_slot,
                  next_leader_slot_after_frag ));

    ctx->next_leader_slot = next_leader_slot_after_frag;
    if( FD_UNLIKELY( currently_leader && !leader_after_frag ) ) {
      /* Shouldn't ever happen, otherwise we need to do a state
         transition out of being leader. */
      FD_LOG_ERR(( "stake update caused us to no longer be leader in an active slot" ));
    }

    /* Nothing to do if we transition into being leader, since it
       will just get picked up by the regular tick loop. */
    return;
}

void
fd_poh_tile_done_packing( fd_poh_tile_ctx_t * ctx, ulong microblocks_in_slot ) {
  FD_TEST( ctx->microblocks_lower_bound<=ctx->max_microblocks_per_slot );
  FD_LOG_INFO(( "done_packing(slot=%lu,seen_microblocks=%lu,microblocks_in_slot=%lu)",
                    ctx->slot,
                    ctx->microblocks_lower_bound,
                    microblocks_in_slot ));
  ctx->microblocks_lower_bound += ctx->max_microblocks_per_slot - microblocks_in_slot;
}

void
fd_poh_tile_publish_microblock( fd_poh_tile_ctx_t * ctx,
                                ulong               sig,
                                ulong               slot,
                                ulong               hashcnt_delta,
                                fd_txn_p_t *        txns,
                                ulong               txn_cnt ) {
  uchar * dst = (uchar *)ctx->get_microblock_buffer_func( ctx->arg );
  FD_TEST( slot>=ctx->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  meta->parent_offset = 1UL+slot-ctx->reset_slot;
  meta->reference_tick = (ctx->hashcnt/ctx->hashcnt_per_tick) % ctx->ticks_per_slot;
  meta->block_complete = !ctx->hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * header = (fd_entry_batch_header_t *)dst;
  header->hashcnt_delta = hashcnt_delta;
  fd_memcpy( header->hash, ctx->hash, 32UL );

  dst += sizeof(fd_entry_batch_header_t);
  ulong payload_sz = 0UL;
  ulong included_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = &txns[ i ];
    if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_memcpy( dst, txn->payload, txn->payload_sz );
    payload_sz += txn->payload_sz;
    dst        += txn->payload_sz;
    included_txn_cnt++;
  }
  header->txn_cnt = included_txn_cnt;

  /* We always have credits to publish here, because we have a burst
     value of 3 credits, and at most we will publish_tick() once and
     then publish_became_leader() once, leaving one credit here to
     publish the microblock. */
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t)+payload_sz;
  ctx->publish_microblock_func( ctx->arg, tspub, sig, sz );
}

void
fd_poh_tile_process_packed_microblock( fd_poh_tile_ctx_t * ctx,
                                       ulong               target_slot,
                                       ulong               sig,
                                       fd_txn_p_t *        txns,
                                       ulong               txn_cnt,
                                       uchar               mixin_hash[ static 32 ] ) {
  if( FD_UNLIKELY( !ctx->microblocks_lower_bound ) ) {
    double tick_per_ns = fd_tempo_tick_per_ns( NULL );
    fd_histf_sample( ctx->first_microblock_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );
  }

  if( FD_UNLIKELY( target_slot!=ctx->next_leader_slot || target_slot!=ctx->slot ) ) {
    FD_LOG_ERR(( "packed too early or late target_slot=%lu, current_slot=%lu. highwater_leader_slot=%lu",
                 target_slot, ctx->slot, ctx->highwater_leader_slot ));
  }

  FD_TEST( ctx->current_leader_slot!=FD_SLOT_NULL );
  FD_TEST( ctx->microblocks_lower_bound<ctx->max_microblocks_per_slot );
  ctx->microblocks_lower_bound += 1UL;

  ulong executed_txn_cnt = 0UL;
  for( ulong i=0; i<txn_cnt; i++ ) { executed_txn_cnt += !!(txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS); }

  /* We don't publish transactions that fail to execute.  If all the
     transctions failed to execute, the microblock would be empty, causing
     solana labs to think it's a tick and complain.  Instead we just skip
     the microblock and don't hash or update the hashcnt. */
  if( FD_UNLIKELY( !executed_txn_cnt ) ) return;

  FD_LOG_INFO(( "rx packed mblk - target_slot: %lu, txn_cnt: %lu", target_slot, executed_txn_cnt ));

  uchar data[ 64 ];
  fd_memcpy( data, ctx->hash, 32UL );
  fd_memcpy( data+32UL, mixin_hash, 32UL );
  fd_sha256_hash( data, 64UL, ctx->hash );

  ctx->hashcnt++;
  FD_TEST( ctx->hashcnt>ctx->last_hashcnt );
  ulong hashcnt_delta = ctx->hashcnt - ctx->last_hashcnt;

  /* The hashing loop above will never leave us exactly one away from
     crossing a tick boundary, so this increment will never cause the
     current tick (or the slot) to change, except in low power mode
     for development, in which case we do need to register the tick
     with the leader bank.  We don't need to publish the tick since
     sending the microblock below is the publishing action. */
  if( FD_UNLIKELY( !(ctx->hashcnt%ctx->hashcnt_per_slot ) ) ) {
    ctx->slot++;
    ctx->hashcnt = 0UL;
  }

  ctx->last_slot    = ctx->slot;
  ctx->last_hashcnt = ctx->hashcnt;

  if( FD_UNLIKELY( !(ctx->hashcnt%ctx->hashcnt_per_tick ) ) ) {
    ctx->register_tick_func( ctx->arg, ctx->current_leader_slot, ctx->hash );
    if( FD_UNLIKELY( ctx->slot>ctx->next_leader_slot ) ) {
      /* We ticked while leader and are no longer leader... transition
         the state machine. */
      fd_poh_tile_no_longer_leader( ctx );
    }
  }

  fd_poh_tile_publish_microblock( ctx, sig, target_slot, hashcnt_delta, txns, txn_cnt );
}

void
fd_poh_tile_during_housekeeping( fd_poh_tile_ctx_t * ctx ) {
  FD_MHIST_COPY( POH_TILE, BEGIN_LEADER_DELAY_SECONDS,     ctx->begin_leader_delay );
  FD_MHIST_COPY( POH_TILE, FIRST_MICROBLOCK_DELAY_SECONDS, ctx->first_microblock_delay );
  FD_MHIST_COPY( POH_TILE, SLOT_DONE_DELAY_SECONDS,        ctx->slot_done_delay );
}

fd_poh_tile_ctx_t *
fd_poh_tile_new( void * scratch,
                 void * arg,
                 fd_poh_tile_get_micoblock_buffer_func_t get_microblock_buffer_func,
                 fd_poh_tile_publish_microblock_func_t   publish_microblock_func,
                 fd_poh_tile_get_pack_buffer_func_t      get_pack_buffer_func,
                 fd_poh_tile_publish_pack_func_t         publish_pack_func,
                 fd_poh_tile_register_tick_func_t        register_tick_func,
                 fd_poh_tile_signal_leader_change_func_t signal_leader_change_func ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_tile_ctx_t ), sizeof( fd_poh_tile_ctx_t ) );
  void * stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * sha256   = FD_SCRATCH_ALLOC_APPEND( l, FD_SHA256_ALIGN,                  FD_SHA256_FOOTPRINT                );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->stake_ci = NONNULL( fd_stake_ci_join( fd_stake_ci_new( stake_ci, &ctx->identity_key ) ) );
  ctx->sha256 = NONNULL( fd_sha256_join( fd_sha256_new( sha256 ) ) );
  ctx->current_leader_slot = FD_SLOT_NULL;

  ctx->slot                  = 0UL;
  ctx->hashcnt               = 0UL;
  ctx->last_hashcnt          = 0UL;
  ctx->highwater_leader_slot = ULONG_MAX;
  ctx->next_leader_slot      = ULONG_MAX;
  ctx->reset_slot            = ULONG_MAX;

  ctx->expect_sequential_leader_slot = ULONG_MAX;

  ctx->microblocks_lower_bound = 0UL;

  fd_histf_join( fd_histf_new( ctx->begin_leader_delay, FD_MHIST_SECONDS_MIN( POH_TILE, BEGIN_LEADER_DELAY_SECONDS ),
                                                        FD_MHIST_SECONDS_MAX( POH_TILE, BEGIN_LEADER_DELAY_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->first_microblock_delay, FD_MHIST_SECONDS_MIN( POH_TILE, FIRST_MICROBLOCK_DELAY_SECONDS  ),
                                                            FD_MHIST_SECONDS_MAX( POH_TILE, FIRST_MICROBLOCK_DELAY_SECONDS  ) ) );
  fd_histf_join( fd_histf_new( ctx->slot_done_delay, FD_MHIST_SECONDS_MIN( POH_TILE, SLOT_DONE_DELAY_SECONDS  ),
                                                     FD_MHIST_SECONDS_MAX( POH_TILE, SLOT_DONE_DELAY_SECONDS  ) ) );

  ctx->arg = arg;
  ctx->get_microblock_buffer_func = get_microblock_buffer_func;
  ctx->publish_microblock_func = publish_microblock_func;
  ctx->get_pack_buffer_func = get_pack_buffer_func;
  ctx->publish_pack_func = publish_pack_func;
  ctx->register_tick_func = register_tick_func;
  ctx->signal_leader_change_func = signal_leader_change_func;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + fd_poh_tile_footprint() ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - fd_poh_tile_footprint(), scratch_top, (ulong)scratch + fd_poh_tile_footprint() ));

  return ctx;
}
