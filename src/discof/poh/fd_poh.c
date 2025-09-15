#include "fd_poh.h"

/* The PoH implementation is at its core a state machine ...

                           +--------+
                           | UNINIT |
                           +--------+
                                |
                  +---------+   |    +---------+
                  |         v   v    v         |
 +-------------------+     +----------+      +------------------+
 |  WAITING_FOR_SLOT |<----| FOLLOWER |----->| WAITING_FOR_BANK |
 +-------------------+     +----------+      +------------------+
                  |             ^              |
                  |             |              |
                  |       +----------+         |
                  |------>|  LEADER  |<--------+
                          +----------+

   The state machine starts UNINIT, but once a snapshot is loaded it
   will transition to follower.

   The state machine is in a resting the state when FOLLOWER, in this
   state it knows a `next_leader_slot` and will continually hash to
   advance towards that slot.  When it reaches the `next_leader_slot`
   it will transition to the WAITING_FOR_BANK state, where it waits for
   the replay stage to tell it some information relevant to that leader
   slot, so that it can start doing mixins and hashing towards the end
   of the block.  When the block ends, the state transitions back to
   follower, even if the next slot is the leader, as we need the replay
   stage to tell us about the new leader slot.

   Sometimes it might happen that we have received the bank from replay
   stage before we have reached the `next_leader_slot`, in which case
   we transition to the WAITING_FOR_SLOT state, where we wait for the
   hash count to reach the leader slot.

   At any time, during any state except UNINIT, we can be suddenly
   "reset" by the replay tile.  Such reset actions may move the reset
   slot backwards or forwards, or set it back to something we have
   already seen before.  BUT, the `next_leader_slot` must always
   advance forward.

   If the PoH machine successfully completes a leader slot, by hashing
   it until the end, then the a completion message is sent back to
   replay with the final blockhash, after which the state machine enters
   the follower state once again, and waits for further instructions
   from replay. */

#define STATE_UNINIT            (0)
#define STATE_FOLLOWER          (1)
#define STATE_WAITING_FOR_BANK  (2)
#define STATE_WAITING_FOR_SLOT  (3)
#define STATE_LEADER            (4)
#define STATE_WAITING_FOR_RESET (5)

FD_FN_CONST ulong
fd_poh_align( void ) {
  return FD_POH_ALIGN;
}

FD_FN_CONST ulong
fd_poh_footprint( void ) {
  return FD_POH_FOOTPRINT;
}

void *
fd_poh_new( void * shmem ) {
  fd_poh_t * poh = (fd_poh_t *)shmem;

  if( FD_UNLIKELY( !poh ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)poh, fd_poh_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  poh->state = STATE_UNINIT;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( poh->magic ) = FD_POH_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)poh;
}

fd_poh_t *
fd_poh_join( void *         shpoh,
             fd_poh_out_t * shred_out,
             fd_poh_out_t * replay_out ) {
  if( FD_UNLIKELY( !shpoh ) ) {
    FD_LOG_WARNING(( "NULL shpoh" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpoh, fd_poh_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpoh" ));
    return NULL;
  }

  fd_poh_t * poh = (fd_poh_t *)shpoh;

  if( FD_UNLIKELY( poh->magic!=FD_POH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  *poh->shred_out = *shred_out;
  *poh->replay_out = *replay_out;

  return poh;
}

static void
transition_to_follower( fd_poh_t *          poh,
                        fd_stem_context_t * stem,
                        int                 completed_leader_slot ) {
  FD_TEST( poh->state==STATE_LEADER || poh->state==STATE_WAITING_FOR_BANK || poh->state==STATE_WAITING_FOR_SLOT );

  if( FD_LIKELY( completed_leader_slot ) ) FD_TEST( poh->state==STATE_LEADER );

  if( FD_LIKELY( poh->state==STATE_LEADER || poh->state==STATE_WAITING_FOR_SLOT ) ) {
    fd_poh_leader_slot_ended_t * dst = fd_chunk_to_laddr( poh->replay_out->mem, poh->replay_out->chunk );
    dst->completed = completed_leader_slot;
    dst->slot      = poh->slot-1UL;
    fd_memcpy( dst->blockhash, poh->hash, 32UL );
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, poh->replay_out->idx, 0UL, poh->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), 0UL, 0UL, tspub );
    poh->replay_out->chunk = fd_dcache_compact_next( poh->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), poh->replay_out->chunk0, poh->replay_out->wmark );
  }

  poh->state = STATE_FOLLOWER;
}

static void
update_hashes_per_tick( fd_poh_t * poh,
                        ulong      hashcnt_per_tick ) {
  if( FD_UNLIKELY( poh->hashcnt_per_tick!=hashcnt_per_tick ) ) {
    if( FD_UNLIKELY( poh->hashcnt_per_tick!=ULONG_MAX ) ) {
      FD_LOG_WARNING(( "hashes per tick changed from %lu to %lu", poh->hashcnt_per_tick, hashcnt_per_tick ));
    }

    /* Recompute derived information about the clock. */
    poh->hashcnt_duration_ns = (double)poh->tick_duration_ns/(double)hashcnt_per_tick;
    poh->hashcnt_per_slot = poh->ticks_per_slot*hashcnt_per_tick;
    poh->hashcnt_per_tick = hashcnt_per_tick;

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

    FD_TEST( poh->last_slot==poh->reset_slot );
    FD_TEST( !poh->last_hashcnt );
    poh->slot = poh->reset_slot;
    poh->hashcnt = 0UL;
  }
}

void
fd_poh_reset( fd_poh_t *          poh,
              fd_stem_context_t * stem,
              ulong               hashcnt_per_tick,       /* The hashcnt per tick of the bank that completed */
              ulong               ticks_per_slot,
              ulong               tick_duration_ns,
              ulong               completed_slot,         /* The slot that successfully produced a bloc */
              uchar const *       completed_blockhash,    /* The hash of the last tick in the produced block */
              ulong               next_leader_slot,       /* The next slot where this node will be leader */
              ulong               max_microblocks_in_slot /* The maximum number of microblocks that may appear in a slot */ ) {
  memcpy( poh->reset_hash, completed_blockhash, 32UL );
  memcpy( poh->hash, completed_blockhash, 32UL );
  poh->slot             = completed_slot+1UL;
  poh->hashcnt          = 0UL;
  poh->last_slot        = poh->slot;
  poh->last_hashcnt     = 0UL;
  poh->reset_slot       = poh->slot;
  poh->next_leader_slot = next_leader_slot;
  poh->max_microblocks_per_slot = max_microblocks_in_slot;

  if( FD_UNLIKELY( poh->state==STATE_UNINIT ) ) {
    poh->tick_duration_ns = tick_duration_ns;
    poh->ticks_per_slot   = ticks_per_slot;
    poh->state = STATE_FOLLOWER;
  } else {
    FD_TEST( tick_duration_ns==poh->tick_duration_ns );
    FD_TEST( ticks_per_slot==poh->ticks_per_slot );
  }
  update_hashes_per_tick( poh, hashcnt_per_tick );

  /* When we reset, we need to allow PoH to tick freely again rather
     than being constrained.  If we are leader after the reset, this
     is OK because we won't tick until we get a bank, and the lower
     bound will be reset with the value from the bank. */
  poh->microblocks_lower_bound = poh->max_microblocks_per_slot;

  if( FD_UNLIKELY( poh->state!=STATE_FOLLOWER ) ) transition_to_follower( poh, stem, 0 );
  if( FD_UNLIKELY( poh->slot==poh->next_leader_slot ) ) poh->state = STATE_WAITING_FOR_BANK;
}

void
fd_poh_begin_leader( fd_poh_t * poh,
                     ulong      slot,
                     ulong      hashcnt_per_tick,
                     ulong      ticks_per_slot,
                     ulong      tick_duration_ns,
                     ulong      max_microblocks_in_slot ) {
  FD_TEST( poh->state==STATE_FOLLOWER || poh->state==STATE_WAITING_FOR_BANK );
  FD_TEST( slot==poh->next_leader_slot );

  poh->max_microblocks_per_slot = max_microblocks_in_slot;

  FD_TEST( tick_duration_ns==poh->tick_duration_ns );
  FD_TEST( ticks_per_slot==poh->ticks_per_slot );
  update_hashes_per_tick( poh, hashcnt_per_tick );

  if( FD_LIKELY( poh->state==STATE_FOLLOWER ) ) poh->state = STATE_WAITING_FOR_SLOT;
  else                                          poh->state = STATE_LEADER;

  poh->slot_done               = 0;
  poh->microblocks_lower_bound = 0UL;

  FD_LOG_INFO(( "begin_leader(slot=%lu, last_slot=%lu, last_hashcnt=%lu)", slot, poh->last_slot, poh->last_hashcnt ));
}

int
fd_poh_have_leader_bank( fd_poh_t const * poh ) {
  return poh->state==STATE_WAITING_FOR_SLOT || poh->state==STATE_LEADER;
}

void
fd_poh_done_packing( fd_poh_t * poh,
                     ulong      microblocks_in_slot ) {
  FD_TEST( poh->state==STATE_LEADER );
  FD_LOG_INFO(( "done_packing(slot=%lu,seen_microblocks=%lu,microblocks_in_slot=%lu)",
                poh->slot,
                poh->microblocks_lower_bound,
                microblocks_in_slot ));
  FD_TEST( poh->microblocks_lower_bound==microblocks_in_slot );
  FD_TEST( poh->microblocks_lower_bound<=poh->max_microblocks_per_slot );
  poh->slot_done = 1;
  poh->microblocks_lower_bound = poh->max_microblocks_per_slot - microblocks_in_slot;
}

static void
publish_tick( fd_poh_t *          poh,
              fd_stem_context_t * stem,
              uchar               hash[ static 32 ],
              int                 is_skipped ) {
  ulong hashcnt = poh->hashcnt_per_tick*(1UL+(poh->last_hashcnt/poh->hashcnt_per_tick));

  uchar * dst = (uchar *)fd_chunk_to_laddr( poh->shred_out->mem, poh->shred_out->chunk );

  FD_TEST( poh->last_slot>=poh->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  if( FD_UNLIKELY( is_skipped ) ) {
    /* We are publishing ticks for a skipped slot, the reference tick
       and block complete flags should always be zero. */
    meta->reference_tick = 0UL;
    meta->block_complete = 0;
  } else {
    meta->reference_tick = hashcnt/poh->hashcnt_per_tick;
    meta->block_complete = hashcnt==poh->hashcnt_per_slot;
  }

  ulong slot = fd_ulong_if( meta->block_complete, poh->slot-1UL, poh->slot );
  meta->parent_offset = 1UL+slot-poh->reset_slot;

  FD_TEST( hashcnt>poh->last_hashcnt );
  ulong hash_delta = hashcnt-poh->last_hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * tick = (fd_entry_batch_header_t *)dst;
  tick->hashcnt_delta = hash_delta;
  fd_memcpy( tick->hash, hash, 32UL );
  tick->txn_cnt = 0UL;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t);
  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  fd_stem_publish( stem, poh->shred_out->idx, sig, poh->shred_out->chunk, sz, 0UL, 0UL, tspub );
  poh->shred_out->chunk = fd_dcache_compact_next( poh->shred_out->chunk, sz, poh->shred_out->chunk0, poh->shred_out->wmark );

  if( FD_UNLIKELY( hashcnt==poh->hashcnt_per_slot ) ) {
    poh->last_slot++;
    poh->last_hashcnt = 0UL;
  } else {
    poh->last_hashcnt = hashcnt;
  }
}

void
fd_poh_advance( fd_poh_t *          poh,
                fd_stem_context_t * stem,
                int *               opt_poll_in,
                int *               charge_busy ) {
  if( FD_UNLIKELY( poh->state==STATE_UNINIT || poh->state==STATE_WAITING_FOR_RESET ) ) return;
  if( FD_UNLIKELY( poh->state==STATE_WAITING_FOR_BANK ) ) {
    /* If we are the leader, but we didn't yet learn what the leader
       bank object is from the replay tile, do not do any hashing. */
    return;
  }

  /* If we have skipped ticks pending because we skipped some slots to
     become leader, register them now one at a time. */
  if( FD_UNLIKELY( poh->state==STATE_LEADER && poh->last_slot<poh->slot ) ) {
    ulong publish_hashcnt = poh->last_hashcnt+poh->hashcnt_per_tick;
    ulong tick_idx = (poh->last_slot*poh->ticks_per_slot+publish_hashcnt/poh->hashcnt_per_tick)%MAX_SKIPPED_TICKS;

    publish_tick( poh, stem, poh->skipped_tick_hashes[ tick_idx ], 1 );

    /* If we are catching up now and publishing a bunch of skipped
       ticks, we do not want to process any incoming microblocks until
       all the skipped ticks have been published out; otherwise we would
       intersperse skipped tick messages with microblocks. */
    *opt_poll_in = 0;
    *charge_busy = 1;
    return;
  }

  int low_power_mode = poh->hashcnt_per_tick==1UL;

  /* If we are the leader, always leave enough capacity in the slot so
     that we can mixin any potential microblocks still coming from the
     pack tile for this slot. */
  ulong max_remaining_microblocks = poh->max_microblocks_per_slot - poh->microblocks_lower_bound;

  /* We don't want to tick over (finish) the slot until pack tell us
     it's done.  If we're waiting on pack, them we clamp to [0, 1]. */
  if( FD_LIKELY( !poh->slot_done && poh->state==STATE_LEADER ) ) max_remaining_microblocks = fd_ulong_max( fd_ulong_min( 1UL, max_remaining_microblocks ), max_remaining_microblocks );

  /* With hashcnt_per_tick hashes per tick, we actually get
     hashcnt_per_tick-1 chances to mixin a microblock.  For each tick
     span that we need to reserve, we also need to reserve the hashcnt
     for the tick, hence the +
     max_remaining_microblocks/(hashcnt_per_tick-1) rounded up.

     However, if hashcnt_per_tick is 1 because we're in low power mode,
     this should probably just be max_remaining_microblocks. */
  ulong max_remaining_ticks_or_microblocks = max_remaining_microblocks;
  if( FD_LIKELY( !low_power_mode ) ) max_remaining_ticks_or_microblocks += (max_remaining_microblocks+poh->hashcnt_per_tick-2UL)/(poh->hashcnt_per_tick-1UL);

  ulong restricted_hashcnt = fd_ulong_if( poh->hashcnt_per_slot>=max_remaining_ticks_or_microblocks, poh->hashcnt_per_slot-max_remaining_ticks_or_microblocks, 0UL );

  ulong min_hashcnt = poh->hashcnt;

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
     min_hashcnt += (ulong)(min_hashcnt%poh->hashcnt_per_tick == (poh->hashcnt_per_tick-1UL)); /* add b_{j+1}, enforcing rule (ii) */
  }
  /* Now figure out how many hashes are needed to "catch up" the hash
     count to the current system clock, and clamp it to the allowed
     range. */
  long now = fd_log_wallclock();
  ulong target_hashcnt;
  if( FD_LIKELY( poh->state==STATE_FOLLOWER ||poh->state==STATE_WAITING_FOR_SLOT ) ) {
    target_hashcnt = (ulong)((double)(now - poh->reset_slot_start_ns) / poh->hashcnt_duration_ns) - (poh->slot-poh->reset_slot)*poh->hashcnt_per_slot;
  } else {
    FD_TEST( poh->state==STATE_LEADER );
    target_hashcnt = (ulong)((double)(now - poh->leader_slot_start_ns) / poh->hashcnt_duration_ns);
  }
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

  ulong next_tick_hashcnt = poh->hashcnt_per_tick * (1UL+(poh->hashcnt/poh->hashcnt_per_tick));
  target_hashcnt = fd_ulong_min( target_hashcnt, next_tick_hashcnt );

  /* We still need to enforce rule (i). We know that min_hashcnt%T !=
     T-1 because of rule (ii).  That means that if target_hashcnt%T ==
     T-1 at this point, target_hashcnt > min_hashcnt (notice the
     strict), so target_hashcnt-1 >= min_hashcnt and is thus still a
     valid choice for target_hashcnt. */
  target_hashcnt -= (ulong)( (!low_power_mode) & ((target_hashcnt%poh->hashcnt_per_tick)==(poh->hashcnt_per_tick-1UL)) );

  FD_TEST( target_hashcnt >= poh->hashcnt       );
  FD_TEST( target_hashcnt >= min_hashcnt        );
  FD_TEST( target_hashcnt <= restricted_hashcnt );

  if( FD_UNLIKELY( poh->hashcnt==target_hashcnt ) ) return; /* Nothing to do, don't publish a tick twice */

  *charge_busy = 1;

  if( FD_LIKELY( poh->hashcnt<target_hashcnt ) ) {
    fd_sha256_hash_32_repeated( poh->hash, poh->hash, target_hashcnt-poh->hashcnt );
    poh->hashcnt = target_hashcnt;
  }

  if( FD_UNLIKELY( poh->hashcnt==poh->hashcnt_per_slot ) ) {
    poh->slot++;
    poh->hashcnt = 0UL;
  }

  switch( poh->state ) {
    case STATE_LEADER: {
      if( FD_UNLIKELY( !(poh->hashcnt%poh->hashcnt_per_tick) ) ) {
        /* We ticked while leader... send an empty microblock (a tick)
           to the shred tile. */
        publish_tick( poh, stem, poh->hash, 0 );
      }
      if( FD_UNLIKELY( poh->slot>poh->next_leader_slot ) ) {
        /* We ticked while leader and are no longer leader... transition
           the state machine. */
        FD_TEST( !max_remaining_microblocks );
        transition_to_follower( poh, stem, 1 );
        poh->state = STATE_WAITING_FOR_RESET;
      }
      break;
    }
    case STATE_WAITING_FOR_SLOT:
    case STATE_FOLLOWER: {
      if( FD_UNLIKELY( !(poh->hashcnt%poh->hashcnt_per_tick ) ) ) {
        /* We finished a tick while not leader... save the current hash
           so it can be played back into the bank when we become the
           leader. */
        ulong tick_idx = (poh->slot*poh->ticks_per_slot+poh->hashcnt/poh->hashcnt_per_tick)%MAX_SKIPPED_TICKS;
        fd_memcpy( poh->skipped_tick_hashes[ tick_idx ], poh->hash, 32UL );

        ulong initial_tick_idx = (poh->last_slot*poh->ticks_per_slot+poh->last_hashcnt/poh->hashcnt_per_tick)%MAX_SKIPPED_TICKS;
        if( FD_UNLIKELY( tick_idx==initial_tick_idx ) ) FD_LOG_ERR(( "Too many skipped ticks from slot %lu to slot %lu, chain must halt", poh->last_slot, poh->slot ));
      }

      FD_TEST( poh->slot<=poh->next_leader_slot );
      if( FD_UNLIKELY( poh->slot==poh->next_leader_slot ) ) {
        /* We ticked while not leader and are now leader... transition
           the state machine. */
        if( FD_LIKELY( poh->state==STATE_FOLLOWER ) ) poh->state = STATE_WAITING_FOR_BANK;
        else                                          poh->state = STATE_LEADER;
      }
      break;
    }
    default: {
      break;
    }
  }
}

static void
publish_microblock( fd_poh_t *          poh,
                    fd_stem_context_t * stem,
                    ulong               slot,
                    ulong               hashcnt_delta,
                    ulong               txn_cnt,
                    fd_txn_p_t const *  txns ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( poh->shred_out->mem, poh->shred_out->chunk );
  FD_TEST( slot>=poh->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  meta->parent_offset = 1UL+slot-poh->reset_slot;
  meta->reference_tick = (poh->hashcnt/poh->hashcnt_per_tick) % poh->ticks_per_slot;
  meta->block_complete = !poh->hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * header = (fd_entry_batch_header_t *)dst;
  header->hashcnt_delta = hashcnt_delta;
  fd_memcpy( header->hash, poh->hash, 32UL );

  dst += sizeof(fd_entry_batch_header_t);
  ulong payload_sz = 0UL;
  ulong included_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * txn = txns + i;
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
  ulong new_sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  fd_stem_publish( stem, poh->shred_out->idx, new_sig, poh->shred_out->chunk, sz, 0UL, 0UL, tspub );
  poh->shred_out->chunk = fd_dcache_compact_next( poh->shred_out->chunk, sz, poh->shred_out->chunk0, poh->shred_out->wmark );
}

void
fd_poh1_mixin( fd_poh_t *          poh,
               fd_stem_context_t * stem,
               ulong               slot,
               uchar const *       hash,
               ulong               txn_cnt,
               fd_txn_p_t const *  txns ) {
  if( FD_UNLIKELY( slot!=poh->next_leader_slot || slot!=poh->slot ) ) {
    FD_LOG_ERR(( "packed too early or late slot=%lu, current_slot=%lu", slot, poh->slot ));
  }

  FD_TEST( poh->state==STATE_LEADER );
  FD_TEST( poh->microblocks_lower_bound<poh->max_microblocks_per_slot );
  poh->microblocks_lower_bound += 1UL;

  ulong executed_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    /* It's important that we check if a transaction is included in the
       block with FD_TXN_P_FLAGS_EXECUTE_SUCCESS since
       actual_consumed_cus may have a nonzero value for excluded
       transactions used for monitoring purposes */
    if( FD_LIKELY( txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) {
      executed_txn_cnt++;
    }
  }

  /* We don't publish transactions that fail to execute.  If all the
     transactions failed to execute, the microblock would be empty,
     causing agave to think it's a tick and complain.  Instead, we just
     skip the microblock and don't hash or update the hashcnt. */
  if( FD_UNLIKELY( !executed_txn_cnt ) ) return;

  uchar data[ 64 ];
  fd_memcpy( data, poh->hash, 32UL );
  fd_memcpy( data+32UL, hash, 32UL );
  fd_sha256_hash( data, 64UL, poh->hash );

  poh->hashcnt++;
  FD_TEST( poh->hashcnt>poh->last_hashcnt );
  ulong hashcnt_delta = poh->hashcnt - poh->last_hashcnt;

  /* The hashing loop above will never leave us exactly one away from
     crossing a tick boundary, so this increment will never cause the
     current tick (or the slot) to change, except in low power mode
     for development, in which case we do need to register the tick
     with the leader bank.  We don't need to publish the tick since
     sending the microblock below is the publishing action. */
  if( FD_UNLIKELY( !(poh->hashcnt%poh->hashcnt_per_slot ) ) ) {
    poh->slot++;
    poh->hashcnt = 0UL;
  }

  poh->last_slot    = poh->slot;
  poh->last_hashcnt = poh->hashcnt;

  if( FD_UNLIKELY( !(poh->hashcnt%poh->hashcnt_per_tick ) ) ) {
    if( FD_UNLIKELY( poh->slot>poh->next_leader_slot ) ) {
      /* We ticked while leader and are no longer leader... transition
         the state machine. */
      transition_to_follower( poh, stem, 1 );
      poh->state = STATE_WAITING_FOR_RESET;
    }
  }

  publish_microblock( poh, stem, slot, hashcnt_delta, txn_cnt, txns );
}
