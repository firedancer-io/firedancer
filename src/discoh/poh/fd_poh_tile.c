#define _GNU_SOURCE

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

#include "../../disco/tiles.h"
#include "../../disco/bundle/fd_bundle_crank.h"
#include "../../disco/pack/fd_pack.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/pod/fd_pod.h"
#include "../../disco/shred/fd_shredder.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/generated/fd_metrics_poh.h"
#include "../../disco/plugin/fd_plugin.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"

#include <string.h>

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
#define MAX_MICROBLOCKS_PER_SLOT (32768UL)

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

#define IN_KIND_BANK  (0)
#define IN_KIND_PACK  (1)
#define IN_KIND_STAKE (2)


typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_poh_in_ctx_t;

typedef struct {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_poh_out_ctx_t;

typedef struct {
  fd_stem_context_t * stem;

  /* Static configuration determined at genesis creation time.  See
     long comment above for more information. */
  ulong  tick_duration_ns;
  ulong  hashcnt_per_tick;
  ulong  ticks_per_slot;

  /* Derived from the above configuration, but we precompute it. */
  double slot_duration_ns;
  double hashcnt_duration_ns;
  ulong  hashcnt_per_slot;
  /* Constant, fixed at initialization.  The maximum number of
     microblocks that the pack tile can publish in each slot. */
  ulong max_microblocks_per_slot;

  /* Consensus-critical slot cost limits. */
  struct {
    ulong slot_max_cost;
    ulong slot_max_vote_cost;
    ulong slot_max_write_cost_per_acct;
  } limits;

  /* The current slot and hashcnt within that slot of the proof of
     history, including hashes we have been producing in the background
     while waiting for our next leader slot. */
  ulong slot;
  ulong hashcnt;
  ulong cus_used;

  /* When we send a microblock on to the shred tile, we need to tell
     it how many hashes there have been since the last microblock, so
     this tracks the hashcnt of the last published microblock.

     If we are skipping slots prior to our leader slot, the last_slot
     will be quite old, and potentially much larger than the number of
     hashcnts in one slot. */
  ulong last_slot;
  ulong last_hashcnt;

  /* If we have published a tick or a microblock for a particular slot
     to the shred tile, we should never become leader for that slot
     again, otherwise we could publish a duplicate block.

     This value tracks the max slot that we have published a tick or
     microblock for so we can prevent this. */
  ulong highwater_leader_slot;

  /* See how this field is used below.  If we have sequential leader
     slots, we don't reset the expected slot end time between the two,
     to prevent clock drift.  If we didn't do this, our 2nd slot would
     end 400ms + `time_for_replay_to_move_slot_and_reset_poh` after
     our 1st, rather than just strictly 400ms. */
  int  lagged_consecutive_leader_start;
  ulong expect_sequential_leader_slot;

  /* There's a race condition ... let's say two banks A and B, bank A
     processes some transactions, then releases the account locks, and
     sends the microblock to PoH to be stamped.  Pack now re-packs the
     same accounts with a new microblock, sends to bank B, bank B
     executes and sends the microblock to PoH, and this all happens fast
     enough that PoH picks the 2nd block to stamp before the 1st.  The
     accounts database changes now are misordered with respect to PoH so
     replay could fail.

     To prevent this race, we order all microblocks and only process
     them in PoH in the order they are produced by pack.  This is a
     little bit over-strict, we just need to ensure that microblocks
     with conflicting accounts execute in order, but this is easiest to
     implement for now. */
  uint expect_pack_idx;

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

  /* The timestamp in nanoseconds of when the reset slot was received.
     This is the timestamp we are building on top of to determine when
     our next leader slot starts. */
  long reset_slot_start_ns;

  /* The timestamp in nanoseconds of when we got the bank for the
     current leader slot. */
  long leader_bank_start_ns;

  /* The hashcnt corresponding to the start of the current reset slot. */
  ulong reset_slot;

  /* The hashcnt at which our next leader slot begins, or ULONG max if
     we have no known next leader slot. */
  ulong next_leader_slot;

  /* If an in progress frag should be skipped */
  int skip_frag;

  ulong max_active_descendant;

  /* If we currently are the leader according the clock AND we have
     received the leader bank for the slot from the replay stage,
     this value will be non-NULL.

     Note that we might be inside our leader slot, but not have a bank
     yet, in which case this will still be NULL.

     It will be NULL for a brief race period between consecutive leader
     slots, as we ping-pong back to replay stage waiting for a new bank.

     Agave refers to this as the "working bank". */
  void const * current_leader_bank;

  fd_sha256_t * sha256;

  fd_multi_epoch_leaders_t * mleaders;

  /* The last sequence number of an outgoing fragment to the shred tile,
     or ULONG max if no such fragment.  See fd_keyswitch.h for details
     of how this is used. */
  ulong shred_seq;

  int halted_switching_key;

  fd_keyswitch_t * keyswitch;
  fd_pubkey_t identity_key;

  /* We need a few pieces of information to compute the right addresses
     for bundle crank information that we need to send to pack. */
  struct {
    int enabled;
    fd_pubkey_t vote_account;
    fd_bundle_crank_gen_t gen[1];
  } bundle;


  /* The Agave client needs to be notified when the leader changes,
     so that they can resume the replay stage if it was suspended waiting. */
  void * signal_leader_change;

  /* These are temporarily set in during_frag so they can be used in
     after_frag once the frag has been validated as not overrun. */
  uchar _txns[ USHORT_MAX ];
  fd_microblock_trailer_t _microblock_trailer[ 1 ];

  int in_kind[ 64 ];
  fd_poh_in_ctx_t in[ 64 ];

  fd_poh_out_ctx_t shred_out[ 1 ];
  fd_poh_out_ctx_t pack_out[ 1 ];
  fd_poh_out_ctx_t plugin_out[ 1 ];

  fd_histf_t begin_leader_delay[ 1 ];
  fd_histf_t first_microblock_delay[ 1 ];
  fd_histf_t slot_done_delay[ 1 ];
  fd_histf_t bundle_init_delay[ 1 ];

  ulong features_activation_avail;
  fd_shred_features_activation_t features_activation[1];

  ulong parent_slot;
  uchar parent_block_id[ 32 ];

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
} fd_poh_ctx_t;

/* The PoH recorder is implemented in Firedancer but for now needs to
   work with Agave, so we have a locking scheme for them to
   co-operate.

   This is because the PoH tile lives in the Agave memory address
   space and their version of concurrency is locking the PoH recorder
   and reading arbitrary fields.

   So we allow them to lock the PoH tile, although with a very bad (for
   them) locking scheme.  By default, the tile has full and exclusive
   access to the data.  If part of Agave wishes to read/write they
   can either,

     1. Rewrite their concurrency to message passing based on mcache
        (preferred, but not feasible).
     2. Signal to the tile they wish to acquire the lock, by setting
        fd_poh_waiting_lock to 1.

   During after_credit, the tile will check if the waiting lock is set
   to 1, and if so, set the returned lock to 1, indicating to the waiter
   that they may now proceed.

   When the waiter is done reading and writing, they restore the
   returned lock value back to zero, and the POH tile continues with its
   day. */

static fd_poh_ctx_t * fd_poh_global_ctx;

static volatile ulong fd_poh_waiting_lock __attribute__((aligned(128UL)));
static volatile ulong fd_poh_returned_lock __attribute__((aligned(128UL)));

/* Agave also needs to write to some mcaches, so we trampoline
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

static poh_link_t gossip_dedup;
static poh_link_t stake_out;
static poh_link_t crds_shred;
static poh_link_t replay_resolv;
static poh_link_t executed_txn;

static poh_link_t replay_plugin;
static poh_link_t gossip_plugin;
static poh_link_t start_progress_plugin;
static poh_link_t vote_listener_plugin;
static poh_link_t validator_info_plugin;

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
                  ulong         data_sz ) {
  while( FD_UNLIKELY( !FD_VOLATILE_CONST( link->mcache ) ) ) FD_SPIN_PAUSE();
  if( FD_UNLIKELY( !link->mem ) ) return; /* link not enabled, don't publish */
  poh_link_wait_credit( link );

  uchar * dst = (uchar *)fd_chunk_to_laddr( link->mem, link->chunk );
  fd_memcpy( dst, data, data_sz );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( link->mcache, link->depth, link->tx_seq, sig, link->chunk, data_sz, 0UL, 0UL, tspub );
  link->chunk = fd_dcache_compact_next( link->chunk, data_sz, link->chunk0, link->wmark );
  link->cr_avail--;
  link->tx_seq++;
}

static void
poh_link_init( poh_link_t *     link,
               fd_topo_t *      topo,
               fd_topo_tile_t * tile,
               ulong            out_idx ) {
  fd_topo_link_t * topo_link = &topo->links[ tile->out_link_id[ out_idx ] ];
  fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ topo_link->dcache_obj_id ].wksp_id ];

  link->mem      = wksp->wksp;
  link->depth    = fd_mcache_depth( topo_link->mcache );
  link->tx_seq   = 0UL;
  link->dcache   = topo_link->dcache;
  link->chunk0   = fd_dcache_compact_chunk0( wksp->wksp, topo_link->dcache );
  link->wmark    = fd_dcache_compact_wmark ( wksp->wksp, topo_link->dcache, topo_link->mtu );
  link->chunk    = link->chunk0;
  link->cr_avail = 0UL;
  link->rx_cnt   = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * _tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<_tile->in_cnt; j++ ) {
      if( _tile->in_link_id[ j ]==topo_link->id && _tile->in_link_reliable[ j ] ) {
        FD_TEST( link->rx_cnt<32UL );
        link->rx_fseqs[ link->rx_cnt++ ] = _tile->in_link_fseq[ j ];
        break;
      }
    }
  }
  FD_COMPILER_MFENCE();
  link->mcache = topo_link->mcache;
  FD_COMPILER_MFENCE();
  FD_TEST( link->mcache );
}

/* To help show correctness, functions that might be called from
   Rust, either directly or indirectly, have this fake "attribute"
   CALLED_FROM_RUST, which is actually nothing.  Calls from Rust
   typically execute on threads did not call fd_boot, so they do not
   have the typical FD_TL variables.  In particular, they cannot use
   normal metrics, and their log messages don't have full context.
   Additionally, Rust functions marked CALLED_FROM_RUST cannot call back
   into a C fd_ext function without causing a deadlock (although the
   other Rust fd_ext functions have a similar problem).

   To prevent annotation from polluting the whole codebase, calls to
   functions outside this file are manually checked and marked as being
   safe at each call rather than annotated. */
#define CALLED_FROM_RUST

static CALLED_FROM_RUST fd_poh_ctx_t *
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

static CALLED_FROM_RUST void
fd_ext_poh_write_unlock( void ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fd_poh_returned_lock ) = 0UL;
}

/* The PoH tile needs to interact with the Agave address space to
   do certain operations that Firedancer hasn't reimplemented yet, a.k.a
   transaction execution.  We have Agave export some wrapper
   functions that we call into during regular tile execution.  These do
   not need any locking, since they are called serially from the single
   PoH tile. */

extern CALLED_FROM_RUST void fd_ext_bank_acquire( void const * bank );
extern CALLED_FROM_RUST void fd_ext_bank_release( void const * bank );
extern CALLED_FROM_RUST void fd_ext_poh_signal_leader_change( void * sender );
extern                  void fd_ext_poh_register_tick( void const * bank, uchar const * hash );

/* fd_ext_poh_initialize is called by Agave on startup to
   initialize the PoH tile with some static configuration, and the
   initial reset slot and hash which it retrieves from a snapshot.

   This function is called by some random Agave thread, but
   it blocks booting of the PoH tile.  The tile will spin until it
   determines that this initialization has happened.

   signal_leader_change is an opaque Rust object that is used to
   tell the replay stage that the leader has changed.  It is a
   Box::into_raw(Arc::increment_strong(crossbeam::Sender)), so it
   has infinite lifetime unless this C code releases the refcnt.

   It can be used with `fd_ext_poh_signal_leader_change` which
   will just issue a nonblocking send on the channel. */

CALLED_FROM_RUST void
fd_ext_poh_initialize( ulong         tick_duration_ns,    /* See clock comments above, will be 6.4 microseconds for mainnet-beta. */
                       ulong         hashcnt_per_tick,    /* See clock comments above, will be 62,500 for mainnet-beta. */
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
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  ctx->slot                = tick_height/ticks_per_slot;
  ctx->hashcnt             = 0UL;
  ctx->cus_used            = 0UL;
  ctx->last_slot           = ctx->slot;
  ctx->last_hashcnt        = 0UL;
  ctx->reset_slot          = ctx->slot;
  ctx->reset_slot_start_ns = fd_log_wallclock(); /* safe to call from Rust */

  memcpy( ctx->reset_hash, last_entry_hash, 32UL );
  memcpy( ctx->hash, last_entry_hash, 32UL );

  ctx->signal_leader_change = signal_leader_change;

  /* Static configuration about the clock. */
  ctx->tick_duration_ns = tick_duration_ns;
  ctx->hashcnt_per_tick = hashcnt_per_tick;
  ctx->ticks_per_slot   = ticks_per_slot;

  /* Recompute derived information about the clock. */
  ctx->slot_duration_ns    = (double)ticks_per_slot*(double)tick_duration_ns;
  ctx->hashcnt_duration_ns = (double)tick_duration_ns/(double)hashcnt_per_tick;
  ctx->hashcnt_per_slot    = ticks_per_slot*hashcnt_per_tick;

  if( FD_UNLIKELY( ctx->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    ctx->max_microblocks_per_slot = ctx->ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    ctx->max_microblocks_per_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ctx->ticks_per_slot*(ctx->hashcnt_per_tick-1UL) );
  }

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

CALLED_FROM_RUST void const *
fd_ext_poh_acquire_leader_bank( void ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();
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

CALLED_FROM_RUST ulong
fd_ext_poh_reset_slot( void ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();
  ulong reset_slot = ctx->reset_slot;
  fd_ext_poh_write_unlock();
  return reset_slot;
}

CALLED_FROM_RUST void
fd_ext_poh_update_active_descendant( ulong max_active_descendant ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();
  ctx->max_active_descendant = max_active_descendant;
  fd_ext_poh_write_unlock();
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

CALLED_FROM_RUST int
fd_ext_poh_reached_leader_slot( ulong * out_leader_slot,
                                ulong * out_reset_slot ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  *out_leader_slot = ctx->next_leader_slot;
  *out_reset_slot  = ctx->reset_slot;

  if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ||
                   ctx->slot<ctx->next_leader_slot ) ) {
    /* Didn't reach our leader slot yet. */
    fd_ext_poh_write_unlock();
    return 0;
  }

  if( FD_UNLIKELY( ctx->halted_switching_key ) ) {
    /* Reached our leader slot, but the leader pipeline is halted
       because we are switching identity key. */
    fd_ext_poh_write_unlock();
    return 0;
  }

  if( FD_LIKELY( ctx->reset_slot==ctx->next_leader_slot ) ) {
    /* We were reset onto our leader slot, because the prior leader
       completed theirs, so we should start immediately, no need for a
       grace period. */
    fd_ext_poh_write_unlock();
    return 1;
  }

  long now_ns = fd_log_wallclock();
  long expected_start_time_ns = ctx->reset_slot_start_ns + (long)((double)(ctx->next_leader_slot-ctx->reset_slot)*ctx->slot_duration_ns);

  /* If a prior leader is still in the process of publishing their slot,
     delay ours to let them finish ... unless they are so delayed that
     we risk getting skipped by the leader following us.  1.2 seconds
     is a reasonable default here, although any value between 0 and 1.6
     seconds could be considered reasonable.  This is arbitrary and
     chosen due to intuition. */

  if( FD_UNLIKELY( now_ns<expected_start_time_ns+(long)(3.0*ctx->slot_duration_ns) ) ) {
    /* If the max_active_descendant is >= next_leader_slot, we waited
       too long and a leader after us started publishing to try and skip
       us.  Just start our leader slot immediately, we might win ... */

    if( FD_LIKELY( ctx->max_active_descendant>=ctx->reset_slot && ctx->max_active_descendant<ctx->next_leader_slot ) ) {
      /* If one of the leaders between the reset slot and our leader
         slot is in the process of publishing (they have a descendant
         bank that is in progress of being replayed), then keep waiting.
         We probably wouldn't get a leader slot out before they
         finished.

         Unless... we are past the deadline to start our slot by more
         than 1.2 seconds, in which case we should probably start it to
         avoid getting skipped by the leader behind us. */
      fd_ext_poh_write_unlock();
      return 0;
    }
  }

  fd_ext_poh_write_unlock();
  return 1;
}

CALLED_FROM_RUST static inline void
publish_plugin_slot_start( fd_poh_ctx_t * ctx,
                           ulong          slot,
                           ulong          parent_slot ) {
  if( FD_UNLIKELY( !ctx->plugin_out->mem ) ) return;

  fd_plugin_msg_slot_start_t * slot_start = (fd_plugin_msg_slot_start_t *)fd_chunk_to_laddr( ctx->plugin_out->mem, ctx->plugin_out->chunk );
  *slot_start = (fd_plugin_msg_slot_start_t){ .slot = slot, .parent_slot = parent_slot };
  fd_stem_publish( ctx->stem, ctx->plugin_out->idx, FD_PLUGIN_MSG_SLOT_START, ctx->plugin_out->chunk, sizeof(fd_plugin_msg_slot_start_t), 0UL, 0UL, 0UL );
  ctx->plugin_out->chunk = fd_dcache_compact_next( ctx->plugin_out->chunk, sizeof(fd_plugin_msg_slot_start_t), ctx->plugin_out->chunk0, ctx->plugin_out->wmark );
}

CALLED_FROM_RUST static inline void
publish_plugin_slot_end( fd_poh_ctx_t * ctx,
                         ulong          slot,
                         ulong          cus_used ) {
  if( FD_UNLIKELY( !ctx->plugin_out->mem ) ) return;

  fd_plugin_msg_slot_end_t * slot_end = (fd_plugin_msg_slot_end_t *)fd_chunk_to_laddr( ctx->plugin_out->mem, ctx->plugin_out->chunk );
  *slot_end = (fd_plugin_msg_slot_end_t){ .slot = slot, .cus_used = cus_used };
  fd_stem_publish( ctx->stem, ctx->plugin_out->idx, FD_PLUGIN_MSG_SLOT_END, ctx->plugin_out->chunk, sizeof(fd_plugin_msg_slot_end_t), 0UL, 0UL, 0UL );
  ctx->plugin_out->chunk = fd_dcache_compact_next( ctx->plugin_out->chunk, sizeof(fd_plugin_msg_slot_end_t), ctx->plugin_out->chunk0, ctx->plugin_out->wmark );
}

extern int
fd_ext_bank_load_account( void const *  bank,
                          int           fixed_root,
                          uchar const * addr,
                          uchar *       owner,
                          uchar *       data,
                          ulong *       data_sz );

CALLED_FROM_RUST static void
publish_became_leader( fd_poh_ctx_t * ctx,
                       ulong          slot,
                       ulong          epoch ) {
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  fd_histf_sample( ctx->begin_leader_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );

  if( FD_UNLIKELY( ctx->lagged_consecutive_leader_start ) ) {
    /* If we are mirroring Agave behavior, the wall clock gets reset
       here so we don't count time spent waiting for a bank to freeze
       or replay stage to actually start the slot towards our 400ms.

       See extended comments in the config file on this option. */
    ctx->reset_slot_start_ns = fd_log_wallclock() - (long)((double)(slot-ctx->reset_slot)*ctx->slot_duration_ns);
  }

  fd_bundle_crank_tip_payment_config_t config[1]             = { 0 };
  fd_acct_addr_t                       tip_receiver_owner[1] = { 0 };

  if( FD_UNLIKELY( ctx->bundle.enabled ) ) {
    long bundle_time = -fd_tickcount();
    fd_acct_addr_t tip_payment_config[1];
    fd_acct_addr_t tip_receiver[1];
    fd_bundle_crank_get_addresses( ctx->bundle.gen, epoch, tip_payment_config, tip_receiver );

    fd_acct_addr_t _dummy[1];
    uchar          dummy[1];

    void const * bank = ctx->current_leader_bank;

    /* Calling rust from a C function that is CALLED_FROM_RUST risks
       deadlock.  In this case, I checked the load_account function and
       ensured it never calls any C functions that acquire the lock. */
    ulong sz1 = sizeof(config), sz2 = 1UL;
    int found1 = fd_ext_bank_load_account( bank, 0, tip_payment_config->b, _dummy->b,             (uchar *)config, &sz1 );
    int found2 = fd_ext_bank_load_account( bank, 0, tip_receiver->b,       tip_receiver_owner->b,          dummy,  &sz2 );
    /* The bundle crank code detects whether the accounts were found by
       whether they have non-zero values (since found and uninitialized
       should be treated the same), so we actually don't really care
       about the value of found{1,2}. */
    (void)found1; (void)found2;
    bundle_time += fd_tickcount();
    fd_histf_sample( ctx->bundle_init_delay, (ulong)bundle_time );
  }

  long slot_start_ns = ctx->reset_slot_start_ns + (long)((double)(slot-ctx->reset_slot)*ctx->slot_duration_ns);

  /* No need to check flow control, there are always credits became when we
     are leader, we will not "become" leader again until we are done, so at
     most one frag in flight at a time. */

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->pack_out->mem, ctx->pack_out->chunk );

  fd_became_leader_t * leader = (fd_became_leader_t *)dst;
  leader->slot_start_ns           = slot_start_ns;
  leader->slot_end_ns             = (long)((double)slot_start_ns + ctx->slot_duration_ns);
  leader->bank                    = ctx->current_leader_bank;
  leader->max_microblocks_in_slot = ctx->max_microblocks_per_slot;
  leader->ticks_per_slot          = ctx->ticks_per_slot;
  leader->total_skipped_ticks     = ctx->ticks_per_slot*(slot-ctx->reset_slot);
  leader->epoch                   = epoch;
  leader->bundle->config[0]       = config[0];

  leader->limits.slot_max_cost                = ctx->limits.slot_max_cost;
  leader->limits.slot_max_vote_cost           = ctx->limits.slot_max_vote_cost;
  leader->limits.slot_max_write_cost_per_acct = ctx->limits.slot_max_write_cost_per_acct;

  memcpy( leader->bundle->last_blockhash,     ctx->reset_hash,    32UL );
  memcpy( leader->bundle->tip_receiver_owner, tip_receiver_owner, 32UL );

  if( FD_UNLIKELY( leader->ticks_per_slot+leader->total_skipped_ticks>=MAX_SKIPPED_TICKS ) )
    FD_LOG_ERR(( "Too many skipped ticks %lu for slot %lu, chain must halt", leader->ticks_per_slot+leader->total_skipped_ticks, slot ));

  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_BECAME_LEADER, 0UL );
  fd_stem_publish( ctx->stem, ctx->pack_out->idx, sig, ctx->pack_out->chunk, sizeof(fd_became_leader_t), 0UL, 0UL, 0UL );
  ctx->pack_out->chunk = fd_dcache_compact_next( ctx->pack_out->chunk, sizeof(fd_became_leader_t), ctx->pack_out->chunk0, ctx->pack_out->wmark );
}

/* The PoH tile knows when it should become leader by waiting for its
   leader slot (with the operating system clock).  This function is so
   that when it becomes the leader, it can be told what the leader bank
   is by the replay stage.  See the notes in the long comment above for
   more on how this works. */

CALLED_FROM_RUST void
fd_ext_poh_begin_leader( void const * bank,
                         ulong        slot,
                         ulong        epoch,
                         ulong        hashcnt_per_tick,
                         ulong        cus_block_limit,
                         ulong        cus_vote_cost_limit,
                         ulong        cus_account_cost_limit ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  FD_TEST( !ctx->current_leader_bank );

  if( FD_UNLIKELY( slot!=ctx->slot ) )             FD_LOG_ERR(( "Trying to begin leader slot %lu but we are now on slot %lu", slot, ctx->slot ));
  if( FD_UNLIKELY( slot!=ctx->next_leader_slot ) ) FD_LOG_ERR(( "Trying to begin leader slot %lu but next leader slot is %lu", slot, ctx->next_leader_slot ));

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

  ctx->current_leader_bank     = bank;
  ctx->microblocks_lower_bound = 0UL;
  ctx->cus_used                = 0UL;

  ctx->limits.slot_max_cost                = cus_block_limit;
  ctx->limits.slot_max_vote_cost           = cus_vote_cost_limit;
  ctx->limits.slot_max_write_cost_per_acct = cus_account_cost_limit;

  /* clamp and warn if we are underutilizing CUs */
  if( FD_UNLIKELY( ctx->limits.slot_max_cost > FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND ) ) {
    FD_LOG_WARNING(( "Underutilizing protocol slot CU limit. protocol_limit=%lu validator_limit=%lu", ctx->limits.slot_max_cost, FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND ));
    ctx->limits.slot_max_cost = FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND;
  }
  if( FD_UNLIKELY( ctx->limits.slot_max_vote_cost > FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND ) ) {
    FD_LOG_WARNING(( "Underutilizing protocol vote CU limit. protocol_limit=%lu validator_limit=%lu", ctx->limits.slot_max_vote_cost, FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND ));
    ctx->limits.slot_max_vote_cost = FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND;
  }
  if( FD_UNLIKELY( ctx->limits.slot_max_write_cost_per_acct > FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND ) ) {
    FD_LOG_WARNING(( "Underutilizing protocol write CU limit. protocol_limit=%lu validator_limit=%lu", ctx->limits.slot_max_write_cost_per_acct, FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND ));
    ctx->limits.slot_max_write_cost_per_acct = FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND;
  }

  /* We are about to start publishing to the shred tile for this slot
     so update the highwater mark so we never republish in this slot
     again.  Also check that the leader slot is greater than the
     highwater, which should have been ensured earlier. */

  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || slot>=ctx->highwater_leader_slot );
  ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), slot );

  publish_became_leader( ctx, slot, epoch );
  FD_LOG_INFO(( "fd_ext_poh_begin_leader(slot=%lu, highwater_leader_slot=%lu, last_slot=%lu, last_hashcnt=%lu)", slot, ctx->highwater_leader_slot, ctx->last_slot, ctx->last_hashcnt ));

  fd_ext_poh_write_unlock();
}

/* Determine what the next slot is in the leader schedule is that we are
   leader.  Includes the current slot.  If we are not leader in what
   remains of the current and next epoch, return ULONG_MAX. */

static inline CALLED_FROM_RUST ulong
next_leader_slot( fd_poh_ctx_t * ctx ) {
  /* If we have published anything in a particular slot, then we
     should never become leader for that slot again. */
  ulong min_leader_slot = fd_ulong_max( ctx->slot, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ) );
  return fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, min_leader_slot, &ctx->identity_key );
}

extern int
fd_ext_admin_rpc_set_identity( uchar const * identity_keypair,
                               int           require_tower );

static inline int FD_FN_SENSITIVE
maybe_change_identity( fd_poh_ctx_t * ctx,
                       int            definitely_not_leader ) {
  if( FD_UNLIKELY( ctx->halted_switching_key && fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    ctx->halted_switching_key = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    return 1;
  }

  /* Cannot change identity while in the middle of a leader slot, else
     poh state machine would become corrupt. */

  int is_leader = !definitely_not_leader && ctx->next_leader_slot!=ULONG_MAX && ctx->slot>=ctx->next_leader_slot;
  if( FD_UNLIKELY( is_leader ) ) return 0;

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    int failed = fd_ext_admin_rpc_set_identity( ctx->keyswitch->bytes, fd_keyswitch_param_query( ctx->keyswitch )==1 );
    explicit_bzero( ctx->keyswitch->bytes, 32UL );
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( failed==-1 ) ) {
      fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_FAILED );
      return 0;
    }

    memcpy( ctx->identity_key.uc, ctx->keyswitch->bytes+32UL, 32UL );

    /* When we switch key, we might have ticked part way through a slot
       that we are now leader in.  This violates the contract of the
       tile, that when we become leader, we have not ticked in that slot
       at all.  To see why this would be bad, consider the case where we
       have ticked almost to the end, and there isn't enough space left
       to reserve the minimum amount of microblocks needed by pack.

       To resolve this, we just reset PoH back to the reset slot, and
       let it try to catch back up quickly. This is OK since the network
       rarely skips. */
    ctx->slot    = ctx->reset_slot;
    ctx->hashcnt = 0UL;
    memcpy( ctx->hash, ctx->reset_hash, 32UL );

    ctx->halted_switching_key = 1;
    ctx->keyswitch->result    = ctx->shred_seq;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  return 0;
}

static CALLED_FROM_RUST void
no_longer_leader( fd_poh_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->current_leader_bank ) ) fd_ext_bank_release( ctx->current_leader_bank );
  /* If we stop being leader in a slot, we can never become leader in
      that slot again, and all in-flight microblocks for that slot
      should be dropped. */
  ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), ctx->slot );
  ctx->current_leader_bank = NULL;
  int identity_changed = maybe_change_identity( ctx, 1 );
  ctx->next_leader_slot = next_leader_slot( ctx );
  if( FD_UNLIKELY( identity_changed ) ) {
    FD_LOG_INFO(( "fd_poh_identity_changed(next_leader_slot=%lu)", ctx->next_leader_slot ));
  }

  FD_COMPILER_MFENCE();
  fd_ext_poh_signal_leader_change( ctx->signal_leader_change );
  FD_LOG_INFO(( "no_longer_leader(next_leader_slot=%lu)", ctx->next_leader_slot ));
}

/* fd_ext_poh_reset is called by the Agave client when a slot on
   the active fork has finished a block and we need to reset our PoH to
   be ticking on top of the block it produced. */

CALLED_FROM_RUST void
fd_ext_poh_reset( ulong         completed_bank_slot, /* The slot that successfully produced a block */
                  uchar const * reset_blockhash,     /* The hash of the last tick in the produced block */
                  ulong         hashcnt_per_tick,    /* The hashcnt per tick of the bank that completed */
                  uchar const * parent_block_id,     /* The block id of the parent block */
                  ulong const * features_activation  /* The activation slot of shred-tile features */ ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  ulong slot_before_reset = ctx->slot;
  int leader_before_reset = ctx->slot>=ctx->next_leader_slot;
  if( FD_UNLIKELY( leader_before_reset && ctx->current_leader_bank ) ) {
    /* If we were in the middle of a leader slot that we notified pack
       pack to start packing for we can never publish into that slot
       again, mark all in-flight microblocks to be dropped. */
    ctx->highwater_leader_slot = fd_ulong_max( fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ), 1UL+ctx->slot );
  }

  ctx->leader_bank_start_ns = fd_log_wallclock(); /* safe to call from Rust */
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
    ctx->reset_slot_start_ns = ctx->leader_bank_start_ns;
  }
  ctx->expect_sequential_leader_slot = ULONG_MAX;

  memcpy( ctx->reset_hash, reset_blockhash, 32UL );
  memcpy( ctx->hash, reset_blockhash, 32UL );
  if( FD_LIKELY( parent_block_id!=NULL ) ) {
    ctx->parent_slot = completed_bank_slot;
    memcpy( ctx->parent_block_id, parent_block_id, 32UL );
  } else {
    FD_LOG_WARNING(( "fd_ext_poh_reset(block_id=null,reset_slot=%lu,parent_slot=%lu) - ignored", completed_bank_slot, ctx->parent_slot ));
  }
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

  /* When we reset, we need to allow PoH to tick freely again rather
     than being constrained.  If we are leader after the reset, this
     is OK because we won't tick until we get a bank, and the lower
     bound will be reset with the value from the bank. */
  ctx->microblocks_lower_bound = ctx->max_microblocks_per_slot;

  if( FD_UNLIKELY( leader_before_reset ) ) {
    /* No longer have a leader bank if we are reset. Replay stage will
       call back again to give us a new one if we should become leader
       for the reset slot.

       The order is important here, ctx->hashcnt must be updated before
       calling no_longer_leader. */
    no_longer_leader( ctx );
  }
  ctx->next_leader_slot = next_leader_slot( ctx );
  FD_LOG_INFO(( "fd_ext_poh_reset(slot=%lu,next_leader_slot=%lu)", ctx->reset_slot, ctx->next_leader_slot ));

  if( FD_UNLIKELY( ctx->slot>=ctx->next_leader_slot ) ) {
    /* We are leader after the reset... two cases: */
    if( FD_LIKELY( ctx->slot==slot_before_reset ) ) {
      /* 1. We are reset onto the same slot we are already leader on.
            This is a common case when we have two leader slots in a
            row, replay stage will reset us to our own slot.  No need to
            do anything here, we already sent a SLOT_START. */
      FD_TEST( leader_before_reset );
    } else {
      /* 2. We are reset onto a different slot. If we were leader
            before, we should first end that slot, then begin the new
            one if we are newly leader now. */
      if( FD_LIKELY( leader_before_reset ) ) publish_plugin_slot_end( ctx, slot_before_reset, ctx->cus_used );
      else                                   publish_plugin_slot_start( ctx, ctx->next_leader_slot, ctx->reset_slot );
    }
  } else {
    if( FD_UNLIKELY( leader_before_reset ) ) publish_plugin_slot_end( ctx, slot_before_reset, ctx->cus_used );
  }

  /* There is a subset of FD_SHRED_FEATURES_ACTIVATION_... slots that
      the shred tile needs to be aware of.  Since their computation
      requires the bank, we are forced (so far) to receive them here
      from the Rust side, before forwarding them to the shred tile as
      POH_PKT_TYPE_FEAT_ACT_SLOT.  This is not elegant, and it should
      be revised in the future (TODO), but it provides a "temporary"
      working solution to handle features activation. */
  fd_memcpy( ctx->features_activation->slots, features_activation, sizeof(fd_shred_features_activation_t) );
  ctx->features_activation_avail = 1UL;

  fd_ext_poh_write_unlock();
}

/* Since it can't easily return an Option<Pubkey>, return 1 for Some and
   0 for None. */
CALLED_FROM_RUST int
fd_ext_poh_get_leader_after_n_slots( ulong n,
                                     uchar out_pubkey[ static 32 ] ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();
  ulong slot = ctx->slot + n;
  fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, slot );

  int copied = 0;
  if( FD_LIKELY( leader ) ) {
    memcpy( out_pubkey, leader, 32UL );
    copied = 1;
  }
  fd_ext_poh_write_unlock();
  return copied;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, FD_SHA256_ALIGN, FD_SHA256_FOOTPRINT );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
publish_tick( fd_poh_ctx_t *      ctx,
              fd_stem_context_t * stem,
              uchar               hash[ static 32 ],
              int                 is_skipped ) {
  ulong hashcnt = ctx->hashcnt_per_tick*(1UL+(ctx->last_hashcnt/ctx->hashcnt_per_tick));

  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );

  FD_TEST( ctx->last_slot>=ctx->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  if( FD_UNLIKELY( is_skipped ) ) {
    /* We are publishing ticks for a skipped slot, the reference tick
       and block complete flags should always be zero. */
    meta->reference_tick = 0UL;
    meta->block_complete = 0;
  } else {
    meta->reference_tick = hashcnt/ctx->hashcnt_per_tick;
    meta->block_complete = hashcnt==ctx->hashcnt_per_slot;
  }

  ulong slot = fd_ulong_if( meta->block_complete, ctx->slot-1UL, ctx->slot );
  meta->parent_offset = 1UL+slot-ctx->reset_slot;

  /* From poh_reset we received the block_id for ctx->parent_slot.
     Now we're telling shred tile to build on parent: (slot-meta->parent_offset).
     The block_id that we're passing is valid iff the two are the same,
     i.e. ctx->parent_slot == (slot-meta->parent_offset). */
  meta->parent_block_id_valid = ctx->parent_slot == (slot-meta->parent_offset);
  if( FD_LIKELY( meta->parent_block_id_valid ) ) {
    fd_memcpy( meta->parent_block_id, ctx->parent_block_id, 32UL );
  }

  FD_TEST( hashcnt>ctx->last_hashcnt );
  ulong hash_delta = hashcnt-ctx->last_hashcnt;

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * tick = (fd_entry_batch_header_t *)dst;
  tick->hashcnt_delta = hash_delta;
  fd_memcpy( tick->hash, hash, 32UL );
  tick->txn_cnt = 0UL;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_entry_batch_meta_t)+sizeof(fd_entry_batch_header_t);
  ulong sig = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  fd_stem_publish( stem, ctx->shred_out->idx, sig, ctx->shred_out->chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_seq = stem->seqs[ ctx->shred_out->idx ];
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );

  if( FD_UNLIKELY( hashcnt==ctx->hashcnt_per_slot ) ) {
    ctx->last_slot++;
    ctx->last_hashcnt = 0UL;
  } else {
    ctx->last_hashcnt = hashcnt;
  }
}

static inline void
publish_features_activation(  fd_poh_ctx_t *      ctx,
                              fd_stem_context_t * stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
  fd_shred_features_activation_t * act_data = (fd_shred_features_activation_t *)dst;
  fd_memcpy( act_data, ctx->features_activation, sizeof(fd_shred_features_activation_t) );

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sz = sizeof(fd_shred_features_activation_t);
  ulong sig = fd_disco_poh_sig( ctx->slot, POH_PKT_TYPE_FEAT_ACT_SLOT, 0UL );
  fd_stem_publish( stem, ctx->shred_out->idx, sig, ctx->shred_out->chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_seq = stem->seqs[ ctx->shred_out->idx ];
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
}

static inline void
after_credit( fd_poh_ctx_t *      ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  ctx->stem = stem;

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
    *opt_poll_in = 0;
    *charge_busy = 1;
    return;
  }
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( ctx->features_activation_avail ) ) {
    /* If we have received an update on features_activation, then
        forward them to the shred tile.  In principle, this should
        happen at most once per slot. */
    publish_features_activation( ctx, stem );
    ctx->features_activation_avail = 0UL;
  }

  int is_leader = ctx->next_leader_slot!=ULONG_MAX && ctx->slot>=ctx->next_leader_slot;
  if( FD_UNLIKELY( is_leader && !ctx->current_leader_bank ) ) {
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

    fd_ext_poh_register_tick( ctx->current_leader_bank, ctx->skipped_tick_hashes[ tick_idx ] );
    publish_tick( ctx, stem, ctx->skipped_tick_hashes[ tick_idx ], 1 );

    /* If we are catching up now and publishing a bunch of skipped
       ticks, we do not want to process any incoming microblocks until
       all the skipped ticks have been published out; otherwise we would
       intersperse skipped tick messages with microblocks. */
    *opt_poll_in = 0;
    *charge_busy = 1;
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
  ulong target_hashcnt;
  if( FD_LIKELY( !is_leader ) ) {
    target_hashcnt = (ulong)((double)(now - ctx->reset_slot_start_ns) / ctx->hashcnt_duration_ns) - (ctx->slot-ctx->reset_slot)*ctx->hashcnt_per_slot;
  } else {
    /* We might have gotten very behind on hashes, but if we are leader
       we want to catch up gradually over the remainder of our leader
       slot, not all at once right now.  This helps keep the tile from
       being oversubscribed and taking a long time to process incoming
       microblocks. */
    long expected_slot_start_ns = ctx->reset_slot_start_ns + (long)((double)(ctx->slot-ctx->reset_slot)*ctx->slot_duration_ns);
    double actual_slot_duration_ns = ctx->slot_duration_ns<(double)(ctx->leader_bank_start_ns - expected_slot_start_ns) ? 0.0 : ctx->slot_duration_ns - (double)(ctx->leader_bank_start_ns - expected_slot_start_ns);
    double actual_hashcnt_duration_ns = actual_slot_duration_ns / (double)ctx->hashcnt_per_slot;
    target_hashcnt = fd_ulong_if( actual_hashcnt_duration_ns==0.0, restricted_hashcnt, (ulong)((double)(now - ctx->leader_bank_start_ns) / actual_hashcnt_duration_ns) );
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

  *charge_busy = 1;

  if( FD_LIKELY( ctx->hashcnt<target_hashcnt ) ) {
    fd_sha256_hash_32_repeated( ctx->hash, ctx->hash, target_hashcnt-ctx->hashcnt );
    ctx->hashcnt = target_hashcnt;
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
    fd_ext_poh_register_tick( ctx->current_leader_bank, ctx->hash );

    /* And send an empty microblock (a tick) to the shred tile. */
    publish_tick( ctx, stem, ctx->hash, 0 );
  }

  if( FD_UNLIKELY( !is_leader && ctx->slot>=ctx->next_leader_slot ) ) {
    /* We ticked while not leader and are now leader... transition
       the state machine. */
    publish_plugin_slot_start( ctx, ctx->next_leader_slot, ctx->reset_slot );
    FD_LOG_INFO(( "fd_poh_ticked_into_leader(slot=%lu, reset_slot=%lu)", ctx->next_leader_slot, ctx->reset_slot ));
  }

  if( FD_UNLIKELY( is_leader && ctx->slot>ctx->next_leader_slot ) ) {
    /* We ticked while leader and are no longer leader... transition
       the state machine. */
    FD_TEST( !max_remaining_microblocks );
    publish_plugin_slot_end( ctx, ctx->next_leader_slot, ctx->cus_used );
    FD_LOG_INFO(( "fd_poh_ticked_outof_leader(slot=%lu)", ctx->next_leader_slot ));

    no_longer_leader( ctx );
    ctx->expect_sequential_leader_slot = ctx->slot;

    double tick_per_ns = fd_tempo_tick_per_ns( NULL );
    fd_histf_sample( ctx->slot_done_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );
    ctx->next_leader_slot = next_leader_slot( ctx );

    if( FD_UNLIKELY( ctx->slot>=ctx->next_leader_slot ) ) {
      /* We finished a leader slot, and are immediately leader for the
         following slot... transition. */
      publish_plugin_slot_start( ctx, ctx->next_leader_slot, ctx->next_leader_slot-1UL );
      FD_LOG_INFO(( "fd_poh_ticked_into_leader(slot=%lu, reset_slot=%lu)", ctx->next_leader_slot, ctx->next_leader_slot-1UL ));
    }
  }
}

static inline void
during_housekeeping( fd_poh_ctx_t * ctx ) {
  if( FD_UNLIKELY( maybe_change_identity( ctx, 0 ) ) ) {
    ctx->next_leader_slot = next_leader_slot( ctx );
    FD_LOG_INFO(( "fd_poh_identity_changed(next_leader_slot=%lu)", ctx->next_leader_slot ));

    /* Signal replay to check if we are leader again, in-case it's stuck
       because everything already replayed. */
    FD_COMPILER_MFENCE();
    fd_ext_poh_signal_leader_change( ctx->signal_leader_change );
  }
}

static inline void
metrics_write( fd_poh_ctx_t * ctx ) {
  FD_MHIST_COPY( POH, BEGIN_LEADER_DELAY_SECONDS,      ctx->begin_leader_delay     );
  FD_MHIST_COPY( POH, FIRST_MICROBLOCK_DELAY_SECONDS,  ctx->first_microblock_delay );
  FD_MHIST_COPY( POH, SLOT_DONE_DELAY_SECONDS,         ctx->slot_done_delay        );
  FD_MHIST_COPY( POH, BUNDLE_INITIALIZE_DELAY_SECONDS, ctx->bundle_init_delay      );
}

static int
before_frag( fd_poh_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)seq;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]!=IN_KIND_BANK && ctx->in_kind[ in_idx ]!=IN_KIND_PACK ) ) return 0;

  uint pack_idx = (uint)fd_disco_bank_sig_pack_idx( sig );
  FD_TEST( ((int)(pack_idx-ctx->expect_pack_idx))>=0L );
  if( FD_UNLIKELY( pack_idx!=ctx->expect_pack_idx ) ) return -1;
  ctx->expect_pack_idx++;

  return 0;
}

static inline void
during_frag( fd_poh_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig,
             ulong          chunk,
             ulong          sz,
             ulong          ctl FD_PARAM_UNUSED ) {
  ctx->skip_frag = 0;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_multi_epoch_leaders_stake_msg_init( ctx->mleaders, fd_type_pun_const( dcache_entry ) );
    return;
  }

  ulong slot;
  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_BANK: {
      slot = fd_disco_bank_sig_slot( sig );
      break;
    }
    case IN_KIND_PACK: {
      slot = fd_disco_poh_sig_slot( sig );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }

  /* The following sequence is possible...

      1. We become leader in slot 10
      2. While leader, we switch to a fork that is on slot 8, where
          we are leader
      3. We get the in-flight microblocks for slot 10

    These in-flight microblocks need to be dropped, so we check
    against the high water mark (highwater_leader_slot) rather than
    the current hashcnt here when determining what to drop.

    We know if the slot is lower than the high water mark it's from a stale
    leader slot, because we will not become leader for the same slot twice
    even if we are reset back in time (to prevent duplicate blocks). */
  int is_frag_for_prior_leader_slot = slot<ctx->highwater_leader_slot;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    /* We now know the real amount of microblocks published, so set an
       exact bound for once we receive them. */
    ctx->skip_frag = 1;
    if( FD_UNLIKELY( is_frag_for_prior_leader_slot ) ) return;

    FD_TEST( ctx->microblocks_lower_bound<=ctx->max_microblocks_per_slot );
    fd_done_packing_t const * done_packing = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
    FD_LOG_INFO(( "done_packing(slot=%lu,seen_microblocks=%lu,microblocks_in_slot=%lu)",
                  ctx->slot,
                  ctx->microblocks_lower_bound,
                  done_packing->microblocks_in_slot ));
    ctx->microblocks_lower_bound += ctx->max_microblocks_per_slot - done_packing->microblocks_in_slot;
    return;
  } else {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>USHORT_MAX ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

    fd_memcpy( ctx->_txns, src, sz-sizeof(fd_microblock_trailer_t) );
    fd_memcpy( ctx->_microblock_trailer, src+sz-sizeof(fd_microblock_trailer_t), sizeof(fd_microblock_trailer_t) );

    ctx->skip_frag = is_frag_for_prior_leader_slot;
  }
}

static void
publish_microblock( fd_poh_ctx_t *      ctx,
                    fd_stem_context_t * stem,
                    ulong               slot,
                    ulong               hashcnt_delta,
                    ulong               txn_cnt ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
  FD_TEST( slot>=ctx->reset_slot );
  fd_entry_batch_meta_t * meta = (fd_entry_batch_meta_t *)dst;
  meta->parent_offset = 1UL+slot-ctx->reset_slot;
  meta->reference_tick = (ctx->hashcnt/ctx->hashcnt_per_tick) % ctx->ticks_per_slot;
  meta->block_complete = !ctx->hashcnt;

  /* Refer to publish_tick() for details on meta->parent_block_id_valid. */
  meta->parent_block_id_valid = ctx->parent_slot == (slot-meta->parent_offset);
  if( FD_LIKELY( meta->parent_block_id_valid ) ) {
    fd_memcpy( meta->parent_block_id, ctx->parent_block_id, 32UL );
  }

  dst += sizeof(fd_entry_batch_meta_t);
  fd_entry_batch_header_t * header = (fd_entry_batch_header_t *)dst;
  header->hashcnt_delta = hashcnt_delta;
  fd_memcpy( header->hash, ctx->hash, 32UL );

  dst += sizeof(fd_entry_batch_header_t);
  ulong payload_sz = 0UL;
  ulong included_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)(ctx->_txns + i*sizeof(fd_txn_p_t));
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
  fd_stem_publish( stem, ctx->shred_out->idx, new_sig, ctx->shred_out->chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_seq = stem->seqs[ ctx->shred_out->idx ];
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
}

static inline void
after_frag( fd_poh_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)tsorig;
  (void)tspub;

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );
    /* It might seem like we do not need to do state transitions in and
       out of being the leader here, since leader schedule updates are
       always one epoch in advance (whether we are leader or not would
       never change for the currently executing slot) but this is not
       true for new ledgers when the validator first boots.  We will
       likely be the leader in slot 1, and get notified of the leader
       schedule for that slot while we are still in it.

       For safety we just handle both transitions, in and out, although
       the only one possible should be into leader. */
    ulong next_leader_slot_after_frag = next_leader_slot( ctx );

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
    if( FD_UNLIKELY( !currently_leader && leader_after_frag ) ) {
      publish_plugin_slot_start( ctx, next_leader_slot_after_frag, ctx->reset_slot );
    }

    return;
  }

  if( FD_UNLIKELY( !ctx->microblocks_lower_bound ) ) {
    double tick_per_ns = fd_tempo_tick_per_ns( NULL );
    fd_histf_sample( ctx->first_microblock_delay, (ulong)((double)(fd_log_wallclock()-ctx->reset_slot_start_ns)/tick_per_ns) );
  }

  ulong target_slot = fd_disco_bank_sig_slot( sig );

  if( FD_UNLIKELY( target_slot!=ctx->next_leader_slot || target_slot!=ctx->slot ) ) {
    FD_LOG_ERR(( "packed too early or late target_slot=%lu, current_slot=%lu. highwater_leader_slot=%lu",
                 target_slot, ctx->slot, ctx->highwater_leader_slot ));
  }

  FD_TEST( ctx->current_leader_bank );
  FD_TEST( ctx->microblocks_lower_bound<ctx->max_microblocks_per_slot );
  ctx->microblocks_lower_bound += 1UL;

  ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
  fd_txn_p_t * txns = (fd_txn_p_t *)(ctx->_txns);
  ulong executed_txn_cnt = 0UL;
  ulong cus_used         = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    /* It's important that we check if a transaction is included in the
       block with FD_TXN_P_FLAGS_EXECUTE_SUCCESS since
       actual_consumed_cus may have a nonzero value for excluded
       transactions used for monitoring purposes */
    if( FD_LIKELY( txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) {
      executed_txn_cnt++;
      cus_used += txns[ i ].bank_cu.actual_consumed_cus;
    }
  }

  /* We don't publish transactions that fail to execute.  If all the
     transactions failed to execute, the microblock would be empty,
     causing agave to think it's a tick and complain.  Instead, we just
     skip the microblock and don't hash or update the hashcnt. */
  if( FD_UNLIKELY( !executed_txn_cnt ) ) return;

  uchar data[ 64 ];
  fd_memcpy( data, ctx->hash, 32UL );
  fd_memcpy( data+32UL, ctx->_microblock_trailer->hash, 32UL );
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

  ctx->cus_used += cus_used;

  if( FD_UNLIKELY( !(ctx->hashcnt%ctx->hashcnt_per_tick ) ) ) {
    fd_ext_poh_register_tick( ctx->current_leader_bank, ctx->hash );
    if( FD_UNLIKELY( ctx->slot>ctx->next_leader_slot ) ) {
      /* We ticked while leader and are no longer leader... transition
         the state machine. */
      publish_plugin_slot_end( ctx, ctx->next_leader_slot, ctx->cus_used );

      no_longer_leader( ctx );

      if( FD_UNLIKELY( ctx->slot>=ctx->next_leader_slot ) ) {
        /* We finished a leader slot, and are immediately leader for the
           following slot... transition. */
        publish_plugin_slot_start( ctx, ctx->next_leader_slot, ctx->next_leader_slot-1UL );
      }
    }
  }

  publish_microblock( ctx, stem, target_slot, hashcnt_delta, txn_cnt );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->poh.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->poh.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_key.uc, identity_key, 32UL );

  if( FD_UNLIKELY( !tile->poh.bundle.vote_account_path[0] ) ) {
    tile->poh.bundle.enabled = 0;
  }
  if( FD_UNLIKELY( tile->poh.bundle.enabled ) ) {
    if( FD_UNLIKELY( !fd_base58_decode_32( tile->poh.bundle.vote_account_path, ctx->bundle.vote_account.uc ) ) ) {
      const uchar * vote_key = fd_keyload_load( tile->poh.bundle.vote_account_path, /* pubkey only: */ 1 );
      fd_memcpy( ctx->bundle.vote_account.uc, vote_key, 32UL );
    }
  }
}

/* The Agave client needs to communicate to the shred tile what
   the shred version is on boot, but shred tile does not live in the
   same address space, so have the PoH tile pass the value through
   via. a shared memory ulong. */

static volatile ulong * fd_shred_version;

void
fd_ext_shred_set_shred_version( ulong shred_version ) {
  while( FD_UNLIKELY( !fd_shred_version ) ) FD_SPIN_PAUSE();
  *fd_shred_version = shred_version;
}

void
fd_ext_poh_publish_gossip_vote( uchar * data,
                                ulong   data_len ) {
  poh_link_publish( &gossip_dedup, 1UL, data, data_len );
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

void
fd_ext_poh_publish_executed_txn( uchar const * data  ) {
  static int lock = 0;

  /* Need to lock since the link publisher is not concurrent, and replay
     happens on a thread pool. */
  for(;;) {
    if( FD_LIKELY( FD_ATOMIC_CAS( &lock, 0, 1 )==0 ) ) break;
    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();
  poh_link_publish( &executed_txn, 0UL, data, 64UL );
  FD_COMPILER_MFENCE();

  FD_VOLATILE(lock) = 0;
}

void
fd_ext_plugin_publish_replay_stage( ulong   sig,
                                    uchar * data,
                                    ulong   data_len ) {
  poh_link_publish( &replay_plugin, sig, data, data_len );
}

void
fd_ext_plugin_publish_genesis_hash( ulong   sig,
                                    uchar * data,
                                    ulong   data_len ) {
  poh_link_publish( &replay_plugin, sig, data, data_len );
}

void
fd_ext_plugin_publish_start_progress( ulong   sig,
                                      uchar * data,
                                      ulong   data_len ) {
  poh_link_publish( &start_progress_plugin, sig, data, data_len );
}

void
fd_ext_plugin_publish_vote_listener( ulong   sig,
                                     uchar * data,
                                     ulong   data_len ) {
  poh_link_publish( &vote_listener_plugin, sig, data, data_len );
}

void
fd_ext_plugin_publish_validator_info( ulong   sig,
                                      uchar * data,
                                      ulong   data_len ) {
  poh_link_publish( &validator_info_plugin, sig, data, data_len );
}

void
fd_ext_plugin_publish_periodic( ulong   sig,
                                uchar * data,
                                ulong   data_len ) {
  poh_link_publish( &gossip_plugin, sig, data, data_len );
}

void
fd_ext_resolv_publish_root_bank( uchar * data,
                                 ulong   data_len ) {
  poh_link_publish( &replay_resolv, 0UL, data, data_len );
}

void
fd_ext_resolv_publish_completed_blockhash( uchar * data,
                                           ulong   data_len ) {
  poh_link_publish( &replay_resolv, 1UL, data, data_len );
}

static inline fd_poh_out_ctx_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_poh_out_ctx_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  void * sha256   = FD_SCRATCH_ALLOC_APPEND( l, FD_SHA256_ALIGN,                  FD_SHA256_FOOTPRINT                );

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ctx->mleaders = NONNULL( fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) ) );
  ctx->sha256   = NONNULL( fd_sha256_join( fd_sha256_new( sha256 ) ) );
  ctx->current_leader_bank = NULL;
  ctx->signal_leader_change = NULL;

  ctx->shred_seq = ULONG_MAX;
  ctx->halted_switching_key = 0;
  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->slot                  = 0UL;
  ctx->hashcnt               = 0UL;
  ctx->last_hashcnt          = 0UL;
  ctx->highwater_leader_slot = ULONG_MAX;
  ctx->next_leader_slot      = ULONG_MAX;
  ctx->reset_slot            = ULONG_MAX;

  ctx->lagged_consecutive_leader_start = tile->poh.lagged_consecutive_leader_start;
  ctx->expect_sequential_leader_slot = ULONG_MAX;

  ctx->expect_pack_idx         = 0U;
  ctx->microblocks_lower_bound = 0UL;

  ctx->max_active_descendant = 0UL;

  if( FD_UNLIKELY( tile->poh.bundle.enabled ) ) {
    ctx->bundle.enabled = 1;
    NONNULL( fd_bundle_crank_gen_init( ctx->bundle.gen, (fd_acct_addr_t const *)tile->poh.bundle.tip_distribution_program_addr,
             (fd_acct_addr_t const *)tile->poh.bundle.tip_payment_program_addr,
             (fd_acct_addr_t const *)ctx->bundle.vote_account.uc,
             (fd_acct_addr_t const *)ctx->bundle.vote_account.uc, "NAN", 0UL ) ); /* last three arguments are properly bogus */
  } else {
    ctx->bundle.enabled = 0;
  }

  ulong poh_shred_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
  FD_TEST( poh_shred_obj_id!=ULONG_MAX );

  fd_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, poh_shred_obj_id ) );
  FD_TEST( fd_shred_version );

  poh_link_init( &gossip_dedup,          topo, tile, out1( topo, tile, "gossip_dedup" ).idx );
  poh_link_init( &stake_out,             topo, tile, out1( topo, tile, "stake_out"    ).idx );
  poh_link_init( &crds_shred,            topo, tile, out1( topo, tile, "crds_shred"   ).idx );
  poh_link_init( &replay_resolv,         topo, tile, out1( topo, tile, "replay_resol" ).idx );
  poh_link_init( &executed_txn,          topo, tile, out1( topo, tile, "executed_txn" ).idx );

  if( FD_LIKELY( tile->poh.plugins_enabled ) ) {
    poh_link_init( &replay_plugin,         topo, tile, out1( topo, tile, "replay_plugi" ).idx );
    poh_link_init( &gossip_plugin,         topo, tile, out1( topo, tile, "gossip_plugi" ).idx );
    poh_link_init( &start_progress_plugin, topo, tile, out1( topo, tile, "startp_plugi" ).idx );
    poh_link_init( &vote_listener_plugin,  topo, tile, out1( topo, tile, "votel_plugin" ).idx );
    poh_link_init( &validator_info_plugin, topo, tile, out1( topo, tile, "valcfg_plugi" ).idx );
  } else {
    /* Mark these mcaches as "available", so the system boots, but the
       memory is not set so nothing will actually get published via.
       the links. */
    FD_COMPILER_MFENCE();
    replay_plugin.mcache = (fd_frag_meta_t*)1;
    gossip_plugin.mcache = (fd_frag_meta_t*)1;
    start_progress_plugin.mcache = (fd_frag_meta_t*)1;
    vote_listener_plugin.mcache = (fd_frag_meta_t*)1;
    validator_info_plugin.mcache = (fd_frag_meta_t*)1;
    FD_COMPILER_MFENCE();
  }

  FD_LOG_INFO(( "PoH waiting to be initialized by Agave client... %lu %lu", fd_poh_waiting_lock, fd_poh_returned_lock ));
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

  if( FD_UNLIKELY( ctx->reset_slot==ULONG_MAX ) ) FD_LOG_ERR(( "PoH was not initialized by Agave client" ));

  fd_histf_join( fd_histf_new( ctx->begin_leader_delay, FD_MHIST_SECONDS_MIN( POH, BEGIN_LEADER_DELAY_SECONDS ),
                                                        FD_MHIST_SECONDS_MAX( POH, BEGIN_LEADER_DELAY_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->first_microblock_delay, FD_MHIST_SECONDS_MIN( POH, FIRST_MICROBLOCK_DELAY_SECONDS  ),
                                                            FD_MHIST_SECONDS_MAX( POH, FIRST_MICROBLOCK_DELAY_SECONDS  ) ) );
  fd_histf_join( fd_histf_new( ctx->slot_done_delay, FD_MHIST_SECONDS_MIN( POH, SLOT_DONE_DELAY_SECONDS  ),
                                                     FD_MHIST_SECONDS_MAX( POH, SLOT_DONE_DELAY_SECONDS  ) ) );

  fd_histf_join( fd_histf_new( ctx->bundle_init_delay, FD_MHIST_SECONDS_MIN( POH, BUNDLE_INITIALIZE_DELAY_SECONDS  ),
                                                       FD_MHIST_SECONDS_MAX( POH, BUNDLE_INITIALIZE_DELAY_SECONDS  ) ) );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );

    if(        !strcmp( link->name, "stake_out" ) ) {
      ctx->in_kind[ i ] = IN_KIND_STAKE;
    } else if( !strcmp( link->name, "pack_poh" ) ) {
      ctx->in_kind[ i ] = IN_KIND_PACK;
    } else if( !strcmp( link->name, "bank_poh"  ) ) {
      ctx->in_kind[ i ] = IN_KIND_BANK;
    } else {
      FD_LOG_ERR(( "unexpected input link name %s", link->name ));
    }
  }

  *ctx->shred_out = out1( topo, tile, "poh_shred" );
  *ctx->pack_out  = out1( topo, tile, "poh_pack" );
  ctx->plugin_out->mem = NULL;
  if( FD_LIKELY( tile->poh.plugins_enabled ) ) {
    *ctx->plugin_out = out1( topo, tile, "poh_plugin" );
  }

  ctx->features_activation_avail = 0UL;
  for( ulong i=0UL; i<FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT; i++ )
    ctx->features_activation->slots[i] = FD_SHRED_FEATURES_ACTIVATION_SLOT_DISABLED;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

/* One tick, one microblock, one plugin slot end, one plugin slot start,
   one leader update, and one features activation. */
#define STEM_BURST (6UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_poh_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_poh_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_poh = {
  .name                     = "poh",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
