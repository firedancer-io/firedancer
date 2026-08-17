#ifndef HEADER_fd_src_discof_poh_fd_poh_h
#define HEADER_fd_src_discof_poh_fd_poh_h

/* Let's say there was a computer, the "leader" computer, that acted as
   a bank.  Users could send it messages saying they wanted to deposit
   money, or transfer it to someone else.

   That's how, for example, Bank of America works but there are problems
   with it.  One simple problem is: the bank can set your balance to
   zero if they don't like you.

   You could try to fix this by having the bank periodically publish the
   list of all account balances and transactions.  If the customers add
   unforgeable signatures to their deposit slips and transfers, then
   the bank cannot zero a balance without it being obvious to everyone.

   There's still problems.  The bank can't lie about your balance now or
   take your money, but it can just not accept deposits on your behalf
   by ignoring you.

   You could fix this by getting a few independent banks together, lets
   say Bank of America, Bank of England, and Westpac, and having them
   rotate who operates the leader computer periodically.  If one bank
   ignores your deposits, you can just wait and send them to the next
   one.

   This is Solana.

   There's still problems of course but they are largely technical.  How
   do the banks agree who is leader?  How do you recover if a leader
   misbehaves?  How do customers verify the transactions aren't forged?
   How do banks receive and publish and verify each others work quickly?
   These are the main technical innovations that enable Solana to work
   well.

   What about Proof of History?

   One particular niche problem is about the leader schedule.  When the
   leader computer is moving from one bank to another, the new bank must
   wait for the old bank to say it's done and provide a final list of
   balances that it can start working off of.  But: what if the computer
   at the old bank crashes and never says its done?

   Does the new leader just take over at some point?  What if the new
   leader is malicious, and says the past thousand leaders crashed, and
   there have been no transactions for days?  How do you check?

   This is what Proof of History solves.  Each bank in the network must
   constantly do a lot of busywork (compute hashes), even when it is not
   leader.

   If the prior thousand leaders crashed, and no transactions happened
   in an hour, the new leader would have to show they did about an hour
   of busywork for everyone else to believe them.

   A better name for this is proof of skipping.  If a leader is skipping
   slots (building off of a slot that is not the direct parent), it must
   prove that it waited a good amount of time to do so.

   It's not a perfect solution.  For one thing, some banks have really
   fast computers and can compute a lot of busywork in a short amount of
   time, allowing them to skip prior slot(s) anyway.  But: there is a
   social component that prevents validators from skipping the prior
   leader slot.  It is easy to detect when this happens and the network
   could respond by ignoring their votes or stake.

   You could come up with other schemes: for example, the network could
   just use wall clock time.  If a new leader publishes a block without
   waiting 400 milliseconds for the prior slot to complete, then there
   is no "proof of skipping" and the nodes ignore the slot.

   These schemes have a problem in that they are not deterministic
   across the network (different computers have different clocks), and
   so they will cause frequent forks which are very expensive to
   resolve.  Even though the proof of history scheme is not perfect,
   it is better than any alternative which is not deterministic.

   With all that background, we can now describe at a high level what
   this PoH tile actually does,

    (1) Whenever any other leader in the network finishes a slot, and
        the slot is determined to be the best one to build off of, this
        tile gets "reset" onto that block, the so called "reset slot".

    (2) The tile is constantly doing busy work, hash(hash(hash(...))) on
        top of the last reset slot, even when it is not leader.

    (3) When the tile becomes leader, it continues hashing from where it
        was.  Typically, the prior leader finishes their slot, so the
        reset slot will be the parent one, and this tile only publishes
        hashes for its own slot.  But if prior slots were skipped, then
        there might be a whole chain already waiting.

    That's pretty much it.  When we are leader, in addition to doing
    busywork, we publish ticks and microblocks to the shred tile.  A
    microblock is a non-empty group of transactions whose hashes are
    mixed-in to the chain, while a tick is a periodic stamp of the
    current hash, with no transactions (nothing mixed in).  We need
    to send both to the shred tile, as ticks are important for other
    validators to verify in parallel.

    As well, the tile should never become leader for a slot that it has
    published anything for, otherwise it may create a duplicate block.

    Some particularly common misunderstandings:

     - PoH is critical to security.

       This largely isn't true.  The target hash rate of the network is
       so slow (1 hash per 500 nanoseconds) that a malicious leader can
       easily catch up if they start from an old hash, and the only
       practical attack prevented is the proof of skipping.  Most of the
       long range attacks in the Solana whitepaper are not relevant.

     - PoH keeps passage of time.

       This is also not true.  The way the network keeps time so it can
       decide who is leader is that, each leader uses their operating
       system clock to time 400 milliseconds and publishes their block
       when this timer expires.

       If a leader just hashed as fast as they could, they could publish
       a block in tens of milliseconds, and the rest of the network
       would happily accept it.  This is why the Solana "clock" as
       determined by PoH is not accurate and drifts over time.

     - PoH prevents transaction reordering by the leader.

       The leader can, in theory, wait until the very end of their
       leader slot to publish anything at all to the network.  They can,
       in particular, hold all received transactions for 400
       milliseconds and then reorder and publish some right at the end
       to advantage certain transactions.

    You might be wondering... if all the PoH chain is helping us do is
    prove that slots were skipped correctly, why do we need to "mix in"
    transactions to the hash value?  Or do anything at all for slots
    where we don't skip the prior slot?

    It's a good question, and the answer is that this behavior is not
    necessary.  An ideal implementation of PoH have no concept of ticks
    or mixins, and would not be part of the TPU pipeline at all.
    Instead, there would be a simple field "skip_proof" on the last
    shred we send for a slot, the hash(hash(...)) value.  This field
    would only be filled in (and only verified by replayers) in cases
    where the slot actually skipped a parent.

    Then what is the "clock?  In Solana, time is constructed as follows:

    HASHES

        The base unit of time is a hash.  Hereafter, any values whose
        units are in hashes are called a "hashcnt" to distinguish them
        from actual hashed values.

        Agave generally defines a constant duration for each tick
        (see below) and then varies the number of hashcnt per tick, but
        as we consider the hashcnt the base unit of time, Firedancer and
        this PoH implementation defines everything in terms of hashcnt
        duration instead.

        In mainnet-beta, testnet, and devnet the hashcnt ticks over
        (increments) every 100 nanoseconds.  The hashcnt rate is
        specified as 500 nanoseconds according to the genesis, but there
        are several features which increase the number of hashes per
        tick while keeping tick duration constant, which make the time
        per hashcnt lower.  These features up to and including the
        `update_hashes_per_tick6` feature are activated on mainnet-beta,
        devnet, and testnet, and are described in the TICKS section
        below.

        Other chains and development environments might have a different
        hashcnt rate in the genesis, or they might not have activated
        the features which increase the rate yet, which we also support.

        In practice, although each validator follows a hashcnt rate of
        100 nanoseconds, the overall observed hashcnt rate of the
        network is a little slower than once every 100 nanoseconds,
        mostly because there are gaps and clock synchronization issues
        during handoff between leaders.  This is referred to as clock
        drift.

    TICKS

        The leader needs to periodically checkpoint the hash value
        associated with a given hashcnt so that they can publish it to
        other nodes for verification.

        On mainnet-beta, testnet, and devnet this occurs once every
        62,500 hashcnts, or approximately once every 6.4 microseconds.
        This value is determined at genesis time, and according to the
        features below, and could be different in development
        environments or on other chains which we support.

        Due to protocol limitations, when mixing in transactions to the
        proof-of-history chain, it cannot occur on a tick boundary (but
        can occur at any other hashcnt).

        Ticks exist mainly so that verification can happen in parallel.
        A verifier computer, rather than needing to do hash(hash(...))
        all in sequence to verify a proof-of-history chain, can do,

         Core 0: hash(hash(...))
         Core 1: hash(hash(...))
         Core 2: hash(hash(...))
         Core 3: hash(hash(...))
         ...

        Between each pair of tick boundaries.

        Solana sometimes calls the current tick the "tick height",
        although it makes more sense to think of it as a counter from
        zero, it's just the number of ticks since the genesis hash.

        There is a set of features which increase the number of hashcnts
        per tick.  These are all deployed on mainnet-beta, devnet, and
        testnet.

           name:             update_hashes_per_tick
           id:               3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B
           hashes per tick:  12,500
           hashcnt duration: 500 nanos

           name:             update_hashes_per_tick2
           id:               EWme9uFqfy1ikK1jhJs8fM5hxWnK336QJpbscNtizkTU
           hashes per tick:  17,500
           hashcnt duration: 357.142857143 nanos

           name:             update_hashes_per_tick3
           id:               8C8MCtsab5SsfammbzvYz65HHauuUYdbY2DZ4sznH6h5
           hashes per tick:  27,500
           hashcnt duration: 227.272727273 nanos

           name:             update_hashes_per_tick4
           id:               8We4E7DPwF2WfAN8tRTtWQNhi98B99Qpuj7JoZ3Aikgg
           hashes per tick:  47,500
           hashcnt duration: 131.578947368 nanos

           name:             update_hashes_per_tick5
           id:               BsKLKAn1WM4HVhPRDsjosmqSg2J8Tq5xP2s2daDS6Ni4
           hashes per tick:  57,500
           hashcnt duration: 108.695652174 nanos

           name:             update_hashes_per_tick6
           id:               FKu1qYwLQSiehz644H6Si65U5ZQ2cp9GxsyFUfYcuADv
           hashes per tick:  62,500
           hashcnt duration: 100 nanos

        In development environments, there is a way to configure the
        hashcnt per tick to be "none" during genesis, for a so-called
        "low power" tick producer.  The idea is not to spin cores during
        development.  This is equivalent to setting the hashcnt per tick
        to be 1, and increasing the hashcnt duration to the desired tick
        duration.

    SLOTS

        Each leader needs to be leader for a fixed amount of time, which
        is called a slot.  During a slot, a leader has an opportunity to
        receive transactions and produce a block for the network,
        although they may miss ("skip") the slot if they are offline or
        not behaving.

        In mainnet-beta, testnet, and devnet a slot is 64 ticks, or
        4,000,000 hashcnts, or approximately 400 milliseconds.

        Due to the way the leader schedule is constructed, each leader
        is always given at least four (4) consecutive slots in the
        schedule. This means when becoming leader you will be leader
        for at least 4 slots, or 1.6 seconds.

        It is rare, although can happen that a leader gets more than 4
        consecutive slots (eg, 8, or 12), if they are lucky with the
        leader schedule generation.

        The number of ticks in a slot is fixed at genesis time, and
        could be different for development or other chains, which we
        support.  There is nothing special about 4 leader slots in a
        row, and this might be changed in future, and the proof of
        history makes no assumptions that this is the case.

    EPOCHS

        Infrequently, the network needs to do certain housekeeping,
        mainly things like collecting rent and deciding on the leader
        schedule.  The length of an epoch is fixed on mainnet-beta,
        devnet and testnet at 420,000 slots, or around ~2 (1.94) days.
        This value is fixed at genesis time, and could be different for
        other chains including development, which we support.  Typically
        in development, epochs are every 8,192 slots, or around  ~1 hour
        (54.61 minutes), although it depends on the number of ticks per
        slot and the target hashcnt rate of the genesis as well.

        In development, epochs need not be a fixed length either.  There
        is a "warmup" option, where epochs start short and grow, which
        is useful for quickly warming up stake during development.

        The epoch is important because it is the only time the leader
        schedule is updated.  The leader schedule is a list of which
        leader is leader for which slot, and is generated by a special
        algorithm that is deterministic and known to all nodes.

        The leader schedule is computed one epoch in advance, so that
        at slot T, we always know who will be leader up until the end
        of slot T+EPOCH_LENGTH.  Specifically, the leader schedule for
        epoch N is computed during the epoch boundary crossing from
        N-2 to N-1. For mainnet-beta, the slots per epoch is fixed and
        will always be 420,000. */

#include "../../disco/pack/fd_pack.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/fd_clock_tile.h"
#include "../../util/fd_util_base.h"
#include "../../ballet/sha256/fd_sha256.h"

/* FD_POH_ALIGN is the alignment needed for a memory region to hold a
   fd_poh_t.  It is a positive integer power of 2. */
#define FD_POH_ALIGN (128UL)

#define FD_POH_MAGIC (0xF17EDA2CE580A000) /* FIREDANCE POH V0 */

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
#define MAX_MICROBLOCKS_PER_SLOT (131072UL)

/* When we are hashing in the background in case a prior leader skips
   their slot, we need to store the result of each tick hash so we can
   publish them when we become leader.  The network requires at least
   one leader slot to publish in each epoch for the leader schedule to
   generate, so in the worst case we might need two full epochs of slots
   to store the hashes.  (Eg, if epoch T only had a published slot in
   position 0 and epoch T+1 only had a published slot right at the end).

   There is a tighter bound: the block data limit of mainnet-beta is
   currently FD_PACK_MAX_DATA_PER_BLOCK, or 27,332,342 bytes per slot.
   At 48 bytes per tick, it is not possible to publish a slot that skips
   569,424 or more prior slots. */
#define MAX_SKIPPED_TICKS (1UL+(FD_PACK_MAX_DATA_PER_BLOCK/48UL))

/* ALPENGLOW.

   Under Alpenglow the shape of a block changes completely and PoH stops
   being a clock.

   A TowerBFT block is a stream of ticks with microblocks interleaved
   between them, and the tick chain is what proves the passage of time.
   PoH free-runs hash(hash(...)) even when not leader so that it can
   prove it waited before skipping a slot.

   An Alpenglow block is

     BlockHeader, microblock, microblock, ..., BlockFooter, tick

   with exactly ONE tick, at the very end, and every entry carrying
   num_hashes==1.  Time is kept by consensus (votor's ParentReady and
   the window timers), not by hashing, so:

     - PoH does no free-running hashing at all.  There is no tick per
       hashcnt boundary to hit, so none of the interleaving rules or the
       restricted_hashcnt arithmetic apply, and the slot clock comes
       from the reset rather than from PoH running ahead.

     - A microblock is hash(hash, mixin), published as it arrives.

     - The single closing tick is hash(hash), computed only once every
       in-flight microblock pack sent for the slot has landed.  Ending
       the block before then would freeze the bank underneath a
       microblock still in flight.

   The BlockHeader must be the FIRST component of the block: a replaying
   peer reads the parent_block_id out of it, and a block whose header is
   not at FEC set 0 is silently deferred by every receiver.  So it is
   published synchronously out of the become_leader frag, before pack is
   told to start packing and therefore before any microblock can exist.

   FD_POH_AG_MARKER_MAX is the largest serialized marker: a footer with
   a full user agent and all three optional certs.  The largest in
   practice is a footer carrying a slow-finalization cert (Final +
   Notar), which is well under this. */

#define FD_POH_AG_MARKER_MAX   (1024UL)

/* Wire sizes of the marker envelope, verified against agave's
   entry/src/block_component.rs wincode schema:

     BlockComponent::BlockMarker  u64 entry count, always 0
     VersionedBlockMarker         u16 tag,  tag_encoding="u16", V1 = 1
     BlockMarkerV1                u8  variant (see below)
     LengthPrefixed<T>            u16 byte length of the inner value,
                                      INCLUDING its own version tag
     VersionedBlockHeader/...     u8  tag, tag_encoding="u8", V1 = 1
     ...payload

   The doc comment in block_component.rs draws the layouts WITHOUT the
   inner Versioned* tag byte; the derive is what is authoritative and it
   emits one.  fd_block_marker.h models it correctly. */

#define FD_POH_AG_MARKER_HDR_SZ  (13UL) /* u64 + u16 + u8 + u16 */
#define FD_POH_AG_MARKER_VER     (1U)

#define FD_POH_AG_VARIANT_FOOTER        (0)
#define FD_POH_AG_VARIANT_HEADER        (1)
#define FD_POH_AG_VARIANT_UPDATE_PARENT (2)
#define FD_POH_AG_VARIANT_GENESIS_CERT  (3)

struct fd_poh_leader_slot_ended {
  int   completed;
  ulong slot;
  uchar blockhash[ 32UL ];
};

typedef struct fd_poh_leader_slot_ended fd_poh_leader_slot_ended_t;

struct fd_poh_out_private {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_poh_out_private fd_poh_out_t;

struct __attribute__((aligned(FD_POH_ALIGN))) fd_poh_private {
  int state;
  int wfs_paused; /* 1 if wait_for_supermajority is active; PoH should not advance */

  /* Static configuration determined at genesis creation time.  See
     long comment above for more information. */
  ulong  tick_duration_ns;
  ulong  hashcnt_per_tick;
  ulong  ticks_per_slot;

  /* Derived from the above configuration, but we precompute it. */
  double slot_duration_ns;
  double hashcnt_duration_ns;
  ulong  hashcnt_per_slot;

  /* The maximum number of real microblocks that the pack tile is
     allowed to publish in each slot.

     While we are leader, PoH internally treats this limit as having
     one extra phantom "microblock" reserved for the done_packing
     message, so that PoH does not finish the slot before pack
     confirms it is done.  Pack itself is configured with the
     un-inflated limit and never publishes more than this many real
     microblocks per slot. */
  ulong max_microblocks_per_slot;

  /* The block id of the completed block. */
  uchar completed_block_id[ 32UL ];

  /* The slot we were reset on (what we are building on top of). */
  ulong reset_slot;
  long  reset_slot_start_ns;

  /* The current slot and hashcnt within that slot of the proof of
     history, including hashes we have been producing in the background
     while waiting for our next leader slot. */
  ulong slot;
  ulong hashcnt;

  ulong next_leader_slot;
  long  leader_slot_start_ns;

  /* When we send a microblock on to the shred tile, we need to tell
     it how many hashes there have been since the last microblock, so
     this tracks the hashcnt of the last published microblock.

     If we are skipping slots prior to our leader slot, the last_slot
     will be quite old, and potentially much larger than the number of
     hashcnts in one slot. */
  ulong last_slot;
  ulong last_hashcnt;

  /* The PoH tile must never drop microblocks that get committed by the
     bank, so it needs to always be able to mixin a microblock hash.
     Mixing in requires incrementing the hashcnt, so we need to ensure
     at all times that there is enough hascnts left in the slot to
     mixin whatever future microblocks pack might produce for it.

     This value tracks that.  At any time, max_microblocks_per_slot
     - microblocks_lower_bound is an upper bound on the maximum number
     of microblocks that might still be received in this slot. */
  ulong microblocks_lower_bound;

  uchar __attribute__((aligned(32UL))) reset_hash[ 32 ];
  uchar __attribute__((aligned(32UL))) hash[ 32 ];

  /* When we are not leader, we need to save the hashes that were
     produced in case the prior leader skips.  If they skip, we will
     replay these skipped hashes into our next leader bank so that
     the slot hashes sysvar can be updated correctly, and also publish
     them to peer nodes as part of our outgoing shreds. */
  uchar skipped_tick_hashes[ MAX_SKIPPED_TICKS ][ 32 ];

  /* ALPENGLOW state.  See the long comment above fd_poh_leader_slot_ended
     for the shape of an alpenglow block. */

  /* Whether the cluster is running alpenglow.  Set from the reset bank,
     which is the only thing that knows, and latched: once alpenglow is
     on it never goes back off within a run, so a later reset carrying a
     stale flag cannot switch the tile back to producing TowerBFT-shaped
     blocks mid-block. */
  int   ag_enabled;

  /* Set once the block has been asked to close, cleared when the tick
     is published.  While set, PoH is waiting for pack's in-flight
     microblocks to drain. */
  int   ag_completing;

  /* The closing tick, computed once ag_completing is set AND every
     microblock accounted for has landed.  ag_tick_ready gates the
     footer+tick publish. */
  int   ag_tick_ready;
  uchar ag_tick_hash[ 32 ];

  /* AGDBG only.  Rate limits the "still draining" debug line in
     ag_advance to once per block; without it the line fires on every
     single after_credit while the block closes. */
  int   ag_drain_logged;

  /* Parent of the block being produced, as the BlockHeader must state
     it.  Under alpenglow the block id is the block's DOUBLE merkle
     root, not the last FEC set's merkle root, so this is not the same
     value as completed_block_id (which is what the shred tile chains
     from).  Kept separately for that reason. */
  ulong     ag_parent_slot;
  fd_hash_t ag_parent_block_id;

  fd_sha256_t * sha256;

  fd_clock_tile_t clock[ 1 ];

  fd_poh_out_t shred_out[ 1 ];
  fd_poh_out_t replay_out[ 1 ];

  ulong magic;
};

typedef struct fd_poh_private fd_poh_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_poh_align( void );

FD_FN_CONST ulong
fd_poh_footprint( void );

void *
fd_poh_new( void * shmem );

fd_poh_t *
fd_poh_join( void *         shpoh,
             fd_poh_out_t * shred_out,
             fd_poh_out_t * replay_out );

void
fd_poh_reset( fd_poh_t *          poh,
              fd_stem_context_t * stem,
              long                timestamp,
              ulong               hashcnt_per_tick,
              ulong               ticks_per_slot,
              ulong               tick_duration_ns,
              ulong               completed_slot,
              uchar const *       completed_blockhash,
              ulong               next_leader_slot,
              ulong               max_microblocks_in_slot,
              uchar const *       completed_block_id );

int
fd_poh_have_leader_bank( fd_poh_t const * poh );

int
fd_poh_hashing_to_leader_slot( fd_poh_t const * poh );

int
fd_poh_must_tick( fd_poh_t const * poh );

int
fd_poh_must_publish_skipped_tick( fd_poh_t const * poh );

void
fd_poh_begin_leader( fd_poh_t * poh,
                     ulong      slot,
                     ulong      hashcnt_per_tick,
                     ulong      ticks_per_slot,
                     ulong      tick_duration_ns,
                     ulong      max_microblocks_in_slot,
                     long       slot_start_ns );

void
fd_poh_done_packing( fd_poh_t * poh,
                     ulong      microblocks_in_slot );

void
fd_poh_advance( fd_poh_t *          poh,
                fd_stem_context_t * stem,
                int *               opt_poll_in,
                int *               charge_busy );

void
fd_poh1_mixin( fd_poh_t *          poh,
               fd_stem_context_t * stem,
               ulong               slot,
               uchar const *       hash,
               ulong               txn_cnt,
               fd_txn_p_t const *  txns );

void
fd_poh_wfs_done( fd_poh_t * poh );

/* fd_poh_update_max_microblocks: Tighten the upper bound on
   max_microblocks_per_slot using the latest bound from pack.
   new_max is the un-inflated bound (pack's view).  PoH inflates
   by +1 which causes it to wait for pack's slot_done message before
   finishing a slot. */
void
fd_poh_update_max_microblocks( fd_poh_t * poh,
                               ulong      new_max );

/* ALPENGLOW ------------------------------------------------------- */

/* fd_poh_ag_enabled returns whether the tile is producing alpenglow
   shaped blocks. */

FD_FN_PURE int
fd_poh_ag_enabled( fd_poh_t const * poh );

/* fd_poh_ag_enable latches alpenglow mode on and re-derives the
   microblock cap.

   Under TowerBFT the cap is min(MAX_MICROBLOCKS_PER_SLOT,
   ticks_per_slot*(hashcnt_per_tick-1)) because each microblock has to
   fit between two ticks.  Alpenglow does not tie microblocks to ticks
   at all -- the block carries as many as fit before the deadline and
   exactly one tick at the end -- and an alpenglow genesis leaves
   hashes_per_tick unset, which would otherwise pin the cap at
   ticks_per_slot, about three orders of magnitude too few. */

void
fd_poh_ag_enable( fd_poh_t * poh );

/* fd_poh_ag_begin_block publishes the BlockHeader for the block that
   begin_leader just opened.  parent_slot / parent_block_id are the
   alpenglow (double merkle root) identity of the parent, from replay.

   MUST be called from the same frag handler as fd_poh_begin_leader, and
   after it.  Publishing here rather than deferring to fd_poh_advance is
   what guarantees the header is ahead of every microblock and lands in
   FEC set 0: pack only learns it is leader from the very same frag, so
   nothing it produces can overtake this.  A header that is not at shred
   index 0 is silently deferred by every receiver. */

void
fd_poh_ag_begin_block( fd_poh_t *          poh,
                       fd_stem_context_t * stem,
                       ulong               parent_slot,
                       fd_hash_t const *   parent_block_id );

/* fd_poh_ag_complete_block asks PoH to end the block in progress.  It
   does not end it: the closing tick may only be computed once every
   microblock pack sent for this slot has landed, so this just sets
   ag_completing and the drain is finished in fd_poh_advance.

   fd_poh_ag_tick_ready reports when the tick has been computed, i.e.
   when the caller may build the footer (it needs the bank frozen, which
   needs the tick registered). */

void
fd_poh_ag_complete_block( fd_poh_t * poh );

FD_FN_PURE int
fd_poh_ag_tick_ready( fd_poh_t const * poh );

/* fd_poh_ag_pending reports that fd_poh_advance has alpenglow work
   outstanding, namely a block that has been asked to close whose tick
   has not been computed yet.  The tile uses it to force an advance:
   under alpenglow fd_poh_must_tick is always false, so otherwise the
   only thing scheduling an advance is the input links going idle, and
   the block would close late (or, if pack keeps the links busy, not at
   all). */

FD_FN_PURE int
fd_poh_ag_pending( fd_poh_t const * poh );

/* fd_poh_ag_publish_footer publishes the footer marker and then the
   closing tick, in that order, and returns the tile to follower state.

   Order on the wire is microblocks..., footer, tick.  The footer has to
   precede the tick because the tick is what carries
   FD_SHRED_DATA_FLAG_SLOT_COMPLETE, and anything after it is not part
   of the block.

   footer/footer_sz is the serialized BlockFooter marker, built by the
   caller with fd_poh_ag_footer_encode once the bank has frozen (the
   footer states the bank hash).  Returns 0 on success, -1 if the footer
   is larger than FD_POH_AG_MARKER_MAX, in which case nothing is
   published and the block never completes. */

int
fd_poh_ag_publish_footer( fd_poh_t *          poh,
                          fd_stem_context_t * stem,
                          uchar const *       footer,
                          ulong               footer_sz );

/* fd_poh_ag_header_encode serializes a BlockHeader marker into out,
   which must have room for FD_POH_AG_MARKER_MAX bytes.  Returns the
   number of bytes written.

   fd_poh_ag_footer_encode does the same for a BlockFooter.  cert /
   cert_sz is the optional serialized FinalCertificate (NULL for none);
   the skip-reward and notar-reward certs are always encoded absent, as
   Firedancer does not produce them.  block_producer_time_nanos is the
   leader's wall clock at block close, which replaying peers clamp
   against the parent's timestamp. */

ulong
fd_poh_ag_header_encode( uchar *           out,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id );

ulong
fd_poh_ag_footer_encode( uchar *           out,
                         fd_hash_t const * bank_hash,
                         long              block_producer_time_nanos,
                         uchar const *     cert,
                         ulong             cert_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_poh_fd_poh_h */
