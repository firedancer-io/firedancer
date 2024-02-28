#ifndef HEADER_fd_src_disco_tiles_poh_fd_poh_tile_h
#define HEADER_fd_src_disco_tiles_poh_fd_poh_tile_h

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

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#include "../../shred/fd_stake_ci.h"
#include "../../../ballet/sha256/fd_sha256.h"

#define FD_POH_TILE_ALIGN (128UL)

struct fd_poh_tile_args {
  char const * identity_key_path;
};

typedef struct fd_poh_tile_args fd_poh_tile_args_t;

struct fd_poh_tile_topo_out {
   fd_wksp_t *      wksp;
   fd_frag_meta_t * mcache;
   void *           dcache;
   ulong            mtu;
   ulong            rx_cnt;
   ulong *          rx_fseq[ 32UL ];
};

typedef struct fd_poh_tile_topo_out fd_poh_tile_topo_out_t;

struct fd_poh_tile_topo {
  ulong       bank_in_cnt;
  fd_wksp_t * bank_in_wksp[ 32 ];
  void *      bank_in_dcache[ 32 ];
  ulong       bank_in_mtu[ 32 ];

  ulong *     pack_busy[ 32 ];
  ulong *     shred_version;

  ulong       stake_in_idx;
  fd_wksp_t * stake_in_wksp;
  void *      stake_in_dcache;
  ulong       stake_in_mtu;

  fd_wksp_t * primary_out_wksp;
  void *      primary_out_dcache;
  ulong       primary_out_mtu;

  fd_poh_tile_topo_out_t gossip_pack_out;
  fd_poh_tile_topo_out_t stake_out;
  fd_poh_tile_topo_out_t crds_shred_out;
};

typedef struct fd_poh_tile_topo fd_poh_tile_topo_t;

struct fd_poh_tile_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_poh_tile_in fd_poh_tile_in_t;

struct __attribute__((aligned(FD_POH_TILE_ALIGN))) fd_poh_tile_private {
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

  fd_poh_tile_in_t bank_in[ 32 ];
  fd_poh_tile_in_t stake_in;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_poh_tile_private fd_poh_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_poh_tile_align( void );

FD_FN_PURE ulong
fd_poh_tile_footprint( fd_poh_tile_args_t const * args );

void
fd_poh_join_privileged( void *                     shpoh,
                        fd_poh_tile_args_t const * args );

fd_poh_tile_t *
fd_poh_tile_join( void *                     shpoh,
                  fd_poh_tile_args_t const * args,
                  fd_poh_tile_topo_t const * topo );

void
fd_poh_tile_run( fd_poh_tile_t *         poh,
                 fd_cnc_t *              cnc,
                 ulong                   in_cnt,
                 fd_frag_meta_t const ** in_mcache,
                 ulong **                in_fseq,
                 fd_frag_meta_t *        mcache,
                 ulong                   out_cnt,
                 ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_poh_fd_poh_tile_h */
