#include "tiles.h"

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
    busywork, we publish ticks and microblocks to the the shred tile.
    A microblock is a non-empty group of transactions whose hashes
    are mixed-in to the chain, while a tick is a periodic stamp of
    the current hash, with no transactions (nothing mixed in).  We
    need to send both to the shred tile, as ticks are important for
    other validators to verify in parallel.

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

        Solana Labs generally defines a constant duration for each tick
        (see below) and then varies the number of hashcnt per tick, but
        as we consider the hashcnt the base unit of time, Firedancer and
        this PoH implementation defines everything in terms of hashcnt
        duration instead.

        In mainnet-beta, testnet, and devnet the hashcnt ticks over
        (increments) every 500 nanoseconds, and that is the target
        hashcnt rate of the proof of history component.  This value is
        fixed at genesis time, and could be different for other chains
        and development environments which we also support.
        
        There is a set of features, which increase the number of hashes
        per tick while keeping tick duration constant, which make the
        time per hashcnt lower although they are not yet deployed.  See
        below in the TICKS section for details of how these change the
        hashcnt duration.

        In practice, although each validator follows a hashcnt rate of
        500 nanoseconds, the overall observed hashcnt rate of the
        network is a little slower than once every 500 nanoseconds,
        mostly because there are gaps and clock synchronization issues
        during handoff between leaders.  This is referred to as clock
        drift.

    TICKS

        The leader needs to periodically checkpoint the hash value
        associated with a given hashcnt so that they can publish it to
        other nodes for verification.
        
        On mainnet-beta, testnet, and devnet this occurs once every
        12,500 hashcnts, or approximately once every 6.25 milliseconds.
        This value is determined at genesis time, and could be
        different in development environments which we support.

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
        per tick.  These are not yet deployed by Solana Labs, and we
        don't support them, but the features are:

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
        800,000 hashcnts, or approximately 400 milliseconds.

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
        of slot T+EPOCH_LENGTH.  Sepcifically, the leader schedule for
        epoch N is computed during the epoch boundary crossing from
        N-2 to N-1. For mainnet-beta, the slots per epoch is fixed and
        will always be 420,000. */

#include "../../../../ballet/pack/fd_pack.h"
#include "../../../../ballet/sha256/fd_sha256.h"
#include "../../../../ballet/bmtree/fd_bmtree.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/bank/fd_bank_abi.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/metrics/generated/fd_metrics_poh.h"
#include "../../../../flamenco/leaders/fd_leaders.h"

/* When we are becoming leader, and we think the prior leader might have
   skipped their slot, we give them a grace period to finish.  In the
   Solana Labs client this is called grace ticks.  This is a courtesy to
   maintain network health, and is not strictly necessary.  It is
   actually advantageous to us as new leader to take over right away and
   give no grace period, since we could generate more fees.

   Here we define the grace period to be two slots, which is taken from
   Solana Labs directly. */
#define GRACE_SLOTS (2UL)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_poh_in_ctx_t;

typedef struct {
  /* Static configuration determined at genesis creation time.  See
     long comment above for more information. */
  ulong hashcnt_duration_ns;
  ulong hashcnt_per_tick;
  ulong ticks_per_slot;

  /* Derived from the above configuration, but we precompute it. */
  ulong hashcnt_per_slot;

  /* The current hashcnt of the proof of history, including hashes
     we have been producing in the background while waiting for our
     next leader slot.

     Assuming a very aggressive future hashcnt rate of 5ns / hash,
     this value would not overflow for about 3000 years. */
  ulong hashcnt;

  /* When we send a microblock on to the shred tile, we need to tell
     it how many hashes there have been since the last microblock, so
     this tracks the hashcnt of the last published microblock.

     As well, the next leader slot that we can transition into will
     always be strictly more than the slot this hashcnt is in, otherwise
     we could potentially become leader for a slot twice. */
  ulong last_hashcnt;

  uchar __attribute__((aligned(32UL))) hash[ 32 ];

  /* The timestamp in nanoseconds of when the reset slot was received.
     This is the timestamp we are building on top of to determine when
     our next leader slot starts. */
  long reset_slot_start_ns;

  /* The hashcnt corresponding to the start of the current reset slot. */
  ulong reset_slot_hashcnt;

  /* The hashcnt at which our next leader slot begins, or ULONG max if
     we have no known next leader slot. */
  ulong next_leader_slot_hashcnt;

  /* A signal to the work loop below to send a fragment to the pack tile
     telling it we are now the leader.  ULONG_MAX if no fragment needs
     to be sent. */
  ulong send_leader_now_for_slot;

  ulong bank_cnt;

  /* If we currently are the leader according the clock AND we have
     received the leader bank for the slot from the replay stage,
     this value will be non-NULL.

     Note that we might be inside our leader slot, but not have a bank
     yet, in which case this will still be NULL.

     It will be NULL for a brief race period between consecutive leader
     slots, as we ping-pong back to replay stage waiting for a new bank.

     Solana Labs refers to this as the "working bank". */
  void const * current_leader_bank;

  /* We need to tell pack when we are done with a microblock so that it
     can reschedule (unlock) the accounts that were in it. */
  ulong * pack_busy[ 32 ];

  fd_sha256_t * sha256;
  void * bmtree;

  ulong stake_in_idx;
  fd_stake_ci_t * stake_ci;

  fd_pubkey_t identity_key;

  /* The Solana Labs client needs to be notified when the leader changes,
     so that they can resume the replay stage if it was suspended waiting. */
  void * signal_leader_change;

  /* These are temporarily set in during_frag so they can be used in
     after_frag once the frag has been validated as not overrun. */
  uchar _txns[ USHORT_MAX ];
  fd_microblock_trailer_t * _microblock_trailer;

  fd_poh_in_ctx_t bank_in[ 32 ];
  fd_poh_in_ctx_t stake_in;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  struct {
    ulong replay_too_early;
    ulong replay_too_late;
    ulong replay_no_longer_leader;
    ulong leader_slot_missed_backpressure;
  } deferred_metrics;
} fd_poh_ctx_t;

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

static fd_poh_ctx_t * fd_poh_global_ctx;

static volatile ulong fd_poh_waiting_lock __attribute__((aligned(128UL)));
static volatile ulong fd_poh_returned_lock __attribute__((aligned(128UL)));

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

/* The PoH tile needs to interact with the Solana Labs address space to
   do certain operations that Firedancer hasn't reimplemented yet, a.k.a
   transaction execution.  We have Solana Labs export some wrapper
   functions that we call into during regular tile execution.  These do
   not need any locking, since they are called serially from the single
   PoH tile. */

extern                  void fd_ext_bank_commit_txns( void const * bank, void const * txns, ulong txn_cnt , void * load_and_execute_output, void * pre_balance_info );
extern CALLED_FROM_RUST void fd_ext_bank_acquire( void const * bank );
extern CALLED_FROM_RUST void fd_ext_bank_release( void const * bank );
extern                  void fd_ext_bank_release_thunks( void * load_and_execute_output );
extern                  void fd_ext_bank_release_pre_balance_info( void * pre_balance_info );
extern CALLED_FROM_RUST void fd_ext_poh_signal_leader_change( void * sender );
extern                  void fd_ext_poh_register_tick( void const * bank, uchar const * hash );

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

CALLED_FROM_RUST void
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
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  ctx->hashcnt             = tick_height*hashcnt_per_tick;
  ctx->last_hashcnt        = ctx->hashcnt;
  ctx->reset_slot_hashcnt  = ctx->hashcnt;
  ctx->reset_slot_start_ns = fd_log_wallclock(); /* safe to call from Rust */

  memcpy( ctx->hash, last_entry_hash, 32UL );

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

CALLED_FROM_RUST int
fd_ext_poh_reached_leader_slot( ulong * out_leader_slot,
                                ulong * out_reset_slot ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

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
    fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, slot-1UL ); /* Safe to call from Rust */
    if( FD_LIKELY( leaders ) ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, slot-1UL ); /* Safe to call from Rust */
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

CALLED_FROM_RUST void
fd_ext_poh_begin_leader( void const * bank,
                         ulong        slot ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  if( FD_UNLIKELY( ctx->current_leader_bank ) ) fd_ext_bank_release( ctx->current_leader_bank );
  ctx->current_leader_bank = NULL;

  ulong current_slot = ctx->hashcnt/ctx->hashcnt_per_slot;
  if( FD_UNLIKELY( slot!=current_slot ) ) {
    /* Already timed out.. nothing to do. */
    if( FD_LIKELY( slot<current_slot ) ) ctx->deferred_metrics.replay_too_early++;
    else                                 ctx->deferred_metrics.replay_too_late ++;

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
    ctx->deferred_metrics.replay_no_longer_leader++;
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

static inline CALLED_FROM_RUST ulong
next_leader_slot_hashcnt( fd_poh_ctx_t * ctx ) {
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
    fd_epoch_leaders_t * leaders = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, current_slot ); /* Safe to call from Rust */
    if( FD_UNLIKELY( !leaders ) ) break;

    while( current_slot<(leaders->slot0+leaders->slot_cnt) ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, current_slot ); /* Safe to call from Rust */
      if( FD_UNLIKELY( !memcmp( leader->key, ctx->identity_key.key, 32UL ) ) ) return current_slot*ctx->hashcnt_per_slot;
      current_slot++;
    }
  }

  return ULONG_MAX;
}

static CALLED_FROM_RUST void
no_longer_leader( fd_poh_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->current_leader_bank ) ) fd_ext_bank_release( ctx->current_leader_bank );
  ctx->current_leader_bank = NULL;
  ctx->next_leader_slot_hashcnt = next_leader_slot_hashcnt( ctx );
  if( FD_UNLIKELY( ctx->send_leader_now_for_slot!=ULONG_MAX ) ) {
    ctx->deferred_metrics.leader_slot_missed_backpressure++;
    ctx->send_leader_now_for_slot = ULONG_MAX;
  }
  FD_COMPILER_MFENCE();
  fd_ext_poh_signal_leader_change( ctx->signal_leader_change );
  FD_LOG_INFO(( "no_longer_leader(next_leader_slot=%lu)", ctx->next_leader_slot_hashcnt/ctx->hashcnt_per_slot ));
}

/* fd_ext_poh_reset is called by the Solana Labs client when a slot on
   the active fork has finished a block and we need to reset our PoH to
   be ticking on top of the block it produced. */

CALLED_FROM_RUST void
fd_ext_poh_reset( ulong         reset_bank_slot, /* The slot that successfully produced a block */
                  uchar const * reset_blockhash  /* The hash of the last tick in the produced block */ ) {
  fd_poh_ctx_t * ctx = fd_ext_poh_write_lock();

  int leader_before_reset = ctx->hashcnt>=ctx->next_leader_slot_hashcnt;

  memcpy( ctx->hash, reset_blockhash, 32UL );
  ctx->hashcnt             = (reset_bank_slot+1UL)*ctx->hashcnt_per_slot;
  ctx->last_hashcnt        = ctx->hashcnt;
  ctx->reset_slot_hashcnt  = ctx->hashcnt;
  ctx->reset_slot_start_ns = fd_log_wallclock(); /* safe to call from Rust */

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

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, FD_SHA256_ALIGN, FD_SHA256_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_poh_ctx_t ) );
}

static void
publish_became_leader( fd_poh_ctx_t *     ctx,
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
publish_tick( fd_poh_ctx_t *     ctx,
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
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_ctx;

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
during_housekeeping( void * _ctx ) {
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_ctx;

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

  FD_MCNT_INC( POH_TILE, REPLAY_TOO_EARLY,                ctx->deferred_metrics.replay_too_early                );
  FD_MCNT_INC( POH_TILE, REPLAY_TOO_LATE,                 ctx->deferred_metrics.replay_too_late                 );
  FD_MCNT_INC( POH_TILE, REPLAY_NO_LONGER_LEADER,         ctx->deferred_metrics.replay_no_longer_leader         );
  FD_MCNT_INC( POH_TILE, LEADER_SLOT_MISSED_BACKPRESSURE, ctx->deferred_metrics.leader_slot_missed_backpressure );
  memset( &ctx->deferred_metrics, '\0', sizeof(ctx->deferred_metrics) );
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

  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_ctx;

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
publish_microblock( fd_poh_ctx_t *     ctx,
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

  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_ctx;

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

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->poh.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->poh.identity_key_path, /* pubkey only: */ 1 );
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
poh_link_init( poh_link_t *     link,
               fd_topo_t *      topo,
               fd_topo_tile_t * tile,
               ulong            out_idx ) {
  fd_topo_link_t * topo_link = &topo->links[ tile->out_link_id[ out_idx ] ];
  fd_topo_wksp_t * wksp = &topo->workspaces[ topo_link->wksp_id ];

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

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
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

  ctx->bank_cnt = tile->in_cnt-1UL;
  ctx->stake_in_idx = tile->in_cnt-1UL;

  fd_shred_version = tile->extra[ tile->in_cnt-1UL ];
  FD_TEST( fd_shred_version );

  memset( &ctx->deferred_metrics, '\0', sizeof(ctx->deferred_metrics) );

  poh_link_init( &gossip_pack, topo, tile, 0UL );
  poh_link_init( &stake_out,   topo, tile, 1UL );
  poh_link_init( &crds_shred,  topo, tile, 2UL );

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

  for( ulong i=0; i<tile->in_cnt-1; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->bank_in[ i ].mem    = link_wksp->wksp;
    ctx->bank_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->bank_in[i].mem, link->dcache );
    ctx->bank_in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->bank_in[i].mem, link->dcache, link->mtu );
    ctx->pack_busy[ i ] = tile->extra[ i ];
    if( FD_UNLIKELY( !ctx->pack_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
  }

  FD_TEST( tile->out_cnt==3UL );

  ctx->stake_in.mem = topo->workspaces[ topo->links[ tile->in_link_id[ tile->in_cnt-1UL ] ].wksp_id ].wksp;
  ctx->stake_in.chunk0 = fd_dcache_compact_chunk0( ctx->stake_in.mem, topo->links[ tile->in_link_id[ tile->in_cnt-1UL ] ].dcache );
  ctx->stake_in.wmark  = fd_dcache_compact_wmark ( ctx->stake_in.mem, topo->links[ tile->in_link_id[ tile->in_cnt-1UL ] ].dcache, topo->links[ tile->in_link_id[ tile->in_cnt-1UL ] ].mtu );

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

fd_topo_run_tile_t fd_tile_poh = {
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 3UL, /* One tick, one microblock, and one leader update. */
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_housekeeping  = during_housekeeping,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
