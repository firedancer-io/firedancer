#ifndef HEADER_fd_src_disco_poh_fd_poh_tile_h
#define HEADER_fd_src_disco_poh_fd_poh_tile_h

#include "../tiles.h"
#include "../shred/fd_stake_ci.h"

/* Common library functions for the Proof of History tile. */

/* When we are becoming leader, and we think the prior leader might have
   skipped their slot, we give them a grace period to finish.  In the
   Solana Labs client this is called grace ticks.  This is a courtesy to
   maintain network health, and is not strictly necessary.  It is
   actually advantageous to us as new leader to take over right away and
   give no grace period, since we could generate more fees.

   Here we define the grace period to be two slots, which is taken from
   Solana Labs directly. */
#define GRACE_SLOTS (2UL)

/* The maximum number of microblocks that pack is allowed to pack into a
   single slot.  This is not consensus critical, and pack could, if we
   let it, produce as many microblocks as it wants, and the slot would
   still be valid.

   We have this here instead so that PoH can estimate slot completion,
   and keep the hashcnt up to date as pack progresses through packing
   the slot.  If this upper bound was not enforced, PoH could tick to
   the last hash of the slot and have no hashes left to mixin incoming
   microblocks from pack, so this upper bound is a coordination
   mechanism so that PoH can progress hashcnts while the slot is active,
   and know that pack will not need those hashcnts later to do mixins. */
#define MAX_MICROBLOCKS_PER_SLOT (16384UL)

struct fd_poh_tile_in_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_poh_tile_in_ctx fd_poh_tile_in_ctx_t;

struct fd_poh_tile_ctx {
  /* Static configuration determined at genesis creation time.  See
     long comment above for more information. */
  double hashcnt_duration_ns;
  ulong  hashcnt_per_tick;
  ulong  ticks_per_slot;

  /* Derived from the above configuration, but we precompute it. */
  ulong hashcnt_per_slot;

  /* The current slot and hashcnt within that slot of the proof of
     history, including hashes we have been producing in the background
     while waiting for our next leader slot. */
  ulong slot;
  ulong hashcnt;

  /* When we send a microblock on to the shred tile, we need to tell
     it how many hashes there have been since the last microblock, so
     this tracks the hashcnt of the last published microblock.

     As well, the next leader slot that we can transition into will
     always be strictly more than the slot this hashcnt is in, otherwise
     we could potentially become leader for a slot twice. */
  ulong last_hashcnt;

  /* See how this field is used below.  If we have sequential leader
     slots, we don't reset the expected slot end time between the two,
     to prevent clock drift.  If we didn't do this, our 2nd slot would
     end 400ms + `time_for_replay_to_move_slot_and_reset_poh` after
     our 1st, rather than just strictly 400ms. */
  ulong expect_sequential_leader_slot;

  /* The PoH tile must never drop microblocks that get committed by the
     bank, so it needs to always be able to mixin a microblock hash.
     Mixing in requires incrementing the hashcnt, so we need to ensure
     at all times that there is enough hascnts left in the slot to
     mixin whatever future microblocks pack might produce for it.

     This value tracks that.  At any time, max_microblocks_per_slot
     - microblocks_lower_bound is an upper bound on the maximum number
     of microblocks that might still be received in this slot. */
  ulong microblocks_lower_bound;

  /* Constant, fixed at initialization.  The maximum number of
     microblocks that the pack tile can publish in each slot. */
  ulong max_microblocks_per_slot;

  uchar __attribute__((aligned(32UL))) hash[ 32 ];

  /* When we are not leader, we need to save the hashes that were
     produced in case the prior leader skips.  If they skip, we will
     replay these skipped hashes into our next leader bank so that
     the slot hashes sysvar can be updated correctly.  We only need 150
     of these, because that's what's required for consensus in the
     sysvar. */
  uchar skipped_slot_hashes[ 150 ][ 32 ];

  /* The timestamp in nanoseconds of when the reset slot was received.
     This is the timestamp we are building on top of to determine when
     our next leader slot starts. */
  long reset_slot_start_ns;

  /* The hashcnt corresponding to the start of the current reset slot. */
  ulong reset_slot_hashcnt;

  /* The hashcnt at which our next leader slot begins, or ULONG max if
     we have no known next leader slot. */
  ulong next_leader_slot_hashcnt;

  /* The current slot where we are leader. If it is set to FD_SLOT_NULL, we are
     not leader. */
  ulong current_leader_slot;


  /* If we have published a tick or a microblock for a particular slot
     to the shred tile, we should never become leader for that slot
     again, otherwise we could publish a duplicate block.

     This value tracks the max slot that we have published a tick or
     microblock for so we can prevent this. */
  ulong highwater_leader_slot;

  fd_sha256_t * sha256;

  fd_stake_ci_t * stake_ci;

  fd_pubkey_t identity_key;

  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;

  fd_frag_meta_t * pack_out_mcache;
  ulong            pack_out_depth;
  ulong            pack_out_seq;
  fd_wksp_t *      pack_out_mem;
  ulong            pack_out_chunk0;
  ulong            pack_out_wmark;
  ulong            pack_out_chunk;

  fd_histf_t begin_leader_delay[ 1 ];
  fd_histf_t first_microblock_delay[ 1 ];
  fd_histf_t slot_done_delay[ 1 ];
};
typedef struct fd_poh_tile_ctx fd_poh_tile_ctx_t;

typedef ulong fd_poh_tile_skipped_hashcnt_iter_t;

FD_PROTOTYPES_BEGIN

ulong
fd_poh_tile_align( void );

ulong
fd_poh_tile_footprint( void );

void
fd_poh_tile_publish_tick( fd_poh_tile_ctx_t * ctx,
                          fd_mux_context_t *  mux );

void
fd_poh_tile_publish_microblock( fd_poh_tile_ctx_t * ctx,
                                fd_mux_context_t *  mux,
                                ulong               sig,
                                ulong               slot,
                                ulong               hashcnt_delta,
                                fd_txn_p_t *        txns,
                                ulong               txn_cnt );
                              
void
fd_poh_tile_initialize( fd_poh_tile_ctx_t * ctx,
                        double              hashcnt_duration_ns, /* See clock comments above, will be 500ns for mainnet-beta. */
                        ulong               hashcnt_per_tick,    /* See clock comments above, will be 12,500 for mainnet-beta. */
                        ulong               ticks_per_slot,      /* See clock comments above, will almost always be 64. */
                        ulong               tick_height,         /* The counter (height) of the tick to start hashing on top of. */
                        uchar const *       last_entry_hash      /* Points to start of a 32 byte region of memory, the hash itself at the tick height. */ );

int
fd_poh_tile_reached_leader_slot( fd_poh_tile_ctx_t * ctx,
                                 ulong *             out_leader_slot,
                                 ulong *             out_reset_slot );

void
fd_poh_tile_publish_became_leader( fd_poh_tile_ctx_t * ctx,
                                   void const *        current_leader_data,
                                   ulong               slot );

ulong
fd_poh_tile_reset_slot( fd_poh_tile_ctx_t const * ctx );

ulong
fd_poh_tile_next_leader_slot_hashcnt( fd_poh_tile_ctx_t * ctx );

void
fd_poh_tile_no_longer_leader( fd_poh_tile_ctx_t * ctx );

int
fd_poh_tile_reset( fd_poh_tile_ctx_t * ctx,
                   ulong               completed_bank_slot, /* The slot that successfully produced a block */
                   uchar const *       reset_blockhash      /* The hash of the last tick in the produced block */ );

int
fd_poh_tile_get_leader_after_n_slots( fd_poh_tile_ctx_t * ctx,
                                      ulong               n,
                                      uchar               out_pubkey[ static 32 ] );

void
fd_poh_tile_during_housekeeping( fd_poh_tile_ctx_t * ctx );

void
fd_poh_tile_begin_leader( fd_poh_tile_ctx_t * ctx,
                          ulong               slot );

int
fd_poh_tile_do_hashing( fd_poh_tile_ctx_t * ctx,
                        int                 is_leader );

int
fd_poh_tile_is_leader( fd_poh_tile_ctx_t * ctx );

int
fd_poh_tile_has_become_leader( fd_poh_tile_ctx_t * ctx,
                               int                 is_leader );
int
fd_poh_tile_is_no_longer_leader( fd_poh_tile_ctx_t * ctx,
                                 int                 is_leader );

void
fd_poh_tile_process_skipped_slot( fd_poh_tile_ctx_t * ctx,
                                  int                 is_leader );

int
fd_poh_tile_has_ticked_while_leader( fd_poh_tile_ctx_t * ctx,
                                     int                 is_leader );

fd_poh_tile_skipped_hashcnt_iter_t
fd_poh_tile_skipped_hashcnt_iter_init( fd_poh_tile_ctx_t * ctx );

fd_poh_tile_skipped_hashcnt_iter_t
fd_poh_tile_skipped_hashcnt_iter_next( fd_poh_tile_ctx_t * ctx, fd_poh_tile_skipped_hashcnt_iter_t iter );

int
fd_poh_tile_skipped_hashcnt_iter_done( fd_poh_tile_ctx_t * ctx, fd_poh_tile_skipped_hashcnt_iter_t iter );

int
fd_poh_tile_skipped_hashcnt_iter_is_slot_boundary( fd_poh_tile_ctx_t * ctx, fd_poh_tile_skipped_hashcnt_iter_t iter );

uchar const *
fd_poh_tile_skipped_hashcnt_iter_slot_hash( fd_poh_tile_ctx_t * ctx, fd_poh_tile_skipped_hashcnt_iter_t iter );

void
fd_poh_tile_unprivileged_init( fd_topo_t *      topo,
                               fd_topo_tile_t * tile,
                               void *           scratch );

ulong
fd_poh_tile_get_slot( fd_poh_tile_ctx_t * ctx );

ulong
fd_poh_tile_get_next_leader_slot( fd_poh_tile_ctx_t * ctx );

ulong
fd_poh_tile_get_last_slot( fd_poh_tile_ctx_t * ctx );

ulong
fd_poh_tile_get_highwater_leader_slot( fd_poh_tile_ctx_t * ctx );

void
fd_poh_tile_stake_update( fd_poh_tile_ctx_t * ctx );

ulong
fd_poh_tile_mixin( fd_poh_tile_ctx_t * ctx,
                   uchar               hash[ static 32 ] );

int
fd_poh_tile_is_at_tick_boundary( fd_poh_tile_ctx_t * ctx );

int
fd_poh_tile_is_no_longer_leader_simple( fd_poh_tile_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_poh_fd_poh_tile_h */
