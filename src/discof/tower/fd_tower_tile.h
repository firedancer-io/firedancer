#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_h

#include "fd_tower_slot_rooted.h"
#include "../../choreo/eqvoc/fd_eqvoc.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/stakes/fd_vote_states.h"

#define FD_TOWER_SIG_SLOT_CONFIRMED (0)
#define FD_TOWER_SIG_SLOT_DONE      (1)
#define FD_TOWER_SIG_SLOT_DUPLICATE (2)
#define FD_TOWER_SIG_SLOT_IGNORED   (3)
// #define FD_TOWER_SIG_SLOT_ROOTED (4)  /* defined in fd_tower_slot_rooted.h */
#define FD_TOWER_SIG_VOTE_STATE     (5)

/* fd_tower_slot_confirmed describes a Tower frag that notifies protocol
   confirmations.  There are multiple confirmation levels:

   - propagation confirmed: a block is propagated if it has received
     votes from at least 1/3 of stake in the cluster.  This threshold is
     important in two contexts:

     1. When becoming leader, we need to check that our previous leader
        block _as of_ the parent slot we're building on, has propagated.
        If it has not propagated, we need to instead retransmit our last
        block that failed to propagate.  The protocol currently allows
        for a grace period of one leader rotation for leader blocks to
        propagate.

     2. When voting, we need to check our previous leader block _as of_
        the slot we're voting for has propagated (unless we're voting
        for one of our own leader blocks).  We cannot vote for a slot in
        which our last ancestor leader block failed to propagate.

   - duplicate confirmed: a block is duplicate confirmed if it has
     received votes from at least 52% of stake in the cluster.  The
     "duplicate" adjective is a bit of a misnomer, and a more accurate
     technical term is equivocation: two (or more) different blocks for
     the same slot.  This threshold is important for consensus safety,
     because it ensures Solana eventually converges to the same block
     per slot.  Specifically fork choice allows choosing a fork if it is
     duplicate confirmed, even if there is equivocation.

   - optimistically confirmed: a block is optimistically confirmed if it
     has received votes from at least 2/3 of stake in the cluster.  This
     threshold is important for end-users, who rely on the "confirmed"
     commitment status of blocks (queryable via RPC) to determine that
     their transaction has landed on a block that will not rollback.
     This is unimplemented in Firedancer and only relevant for RPC.
     (TODO verify this?)

   - super confirmed: same as optimistic, but the stake threshold is 4/5
     of stake.  This is used during boot for `--wait-for-supermajority`.

   It's possible Firedancer reaches a confirmation level before the
   block has actually been replayed.  Firedancer listens to votes from
   both Gossip and TPU, so if a given block id has received enough votes
   it might get "forward-confirmed".

   Tower will also notify of forward confirmations, denoted by the `fwd`
   field on the fd_tower_slot_confirmed frag.  Forward confirmations are
   only for the given block, and do not imply the ancestry chain leading
   up to the block are also confirmed.  This is distinct from replay
   confirmations, which are only emitted after replaying a block (`fwd`
   = 0), and imply the ancestry chain up from that block is also
   confirmed.  Forward confirmations are needed for both repair (in case
   we never got the block over Turbine) and for RPC (since RPC needs to
   know about confirmations even if replay is behind).

   Other guarantees include that the confirmation frags with `fwd` = 0
   are delivered in-order with no gaps from tower (there still might be
   skipped slots, but no gaps means you will always receive an ancestor
   block's confirmation before its descendants).  That is, if a consumer
   receives a confirmation frag for slot N, it will have prior received
   confirmations for all ancestor slots N - 1, N - 2, ... (if they are
   not skipped / on a different fork). */

#define FD_TOWER_SLOT_CONFIRMED_PROPAGATED (0)
#define FD_TOWER_SLOT_CONFIRMED_DUPLICATE  (1)
#define FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC (2)
#define FD_TOWER_SLOT_CONFIRMED_SUPER      (3)
#define FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT  (4)
#define FD_TOWER_SLOT_CONFIRMED_LEVELS     ({ FD_TOWER_SLOT_CONFIRMED_PROPAGATED, FD_TOWER_SLOT_CONFIRMED_DUPLICATE, FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC, FD_TOWER_SLOT_CONFIRMED_SUPER })

struct fd_tower_slot_confirmed {
  int       level;    /* the confirmation level, see FD_TOWER_SLOT_CONFIRMED_{...} above */
  int       fwd;      /* whether this is a "forward confirmation" ie. we have not yet replayed but the slot is confirmed based on gossip and TPU votes */
  ulong     slot;     /* slot being confirmed (in general, a slot being confirmed more than once is possible but highly unlikely ) */
  fd_hash_t block_id; /* block id being confirmed (guaranteed unique) */
};
typedef struct fd_tower_slot_confirmed fd_tower_slot_confirmed_t;

/* In response to finishing replay of a slot, the tower tile will
   produce both a block to vote for and block to reset to, and
   potentially advance the root. */

struct fd_tower_slot_done {

  /* This tower_slot_done message is 1-to-1 with the completion of a
     replayed slot.  When that slot was done, the bank_idx was sent to
     tower, which tower used to query the bank and populate the vote
     accounts.  Tower needs to send back the bank_idx to replay so it
     can decrement the reference count on the bank. */

  ulong replay_slot;
  ulong replay_bank_idx;

  /* The slot being voted on.  There is not always a vote slot (locked
     out, failed switch threshhold, etc.) and will be set to ULONG_MAX
     when there is no slot to vote on.  When set, the vote slot is used
     by the vote sending tile to do some internal book-keeping related
     to leader targeting. */

  ulong vote_slot;

  /* The slot to reset leader pipeline to.  Unlike vote slot, the reset
     slot is always set and represents the consensus fork to build on.
     It may be unchanged since the last slot done.  reset_block_id is
     a unique identifier in case there are multiple blocks for the reset
     slot due to equivocation. */

  ulong     reset_slot;
  fd_hash_t reset_block_id;

  /* Sometimes, finishing replay of a slot may cause a new slot to be
     rooted.  If this happens, new root will be 1 and both root_slot and
     root_block_id will be set to the new root values accordingly.
     Otherwise, new_root will be 0 and root_slot and root_block_id will
     be undefined.  Note it is possible tower emits a new root slot but
     the new root slot's block_id is unavailable (eg. it is an old tower
     vote that precedes the snapshot slot).  In this case new_root will
     _not_ be set to 1. */

  ulong     root_slot;
  fd_hash_t root_block_id;

  /* The number of leaves in the forks tree. */

  ulong active_fork_cnt;

  /* This always contains a vote transaction with our current tower,
     regardless of whether there is a new vote slot or not (ie. vote
     slot can be ULONG_MAX and vote_txn will contain a txn of our
     current tower).  The vote is not yet signed.  This is necessary to
     support refreshing our last vote, ie. we retransmit our vote even
     when we are locked out / can't switch vote forks.  If the vote
     account's authorized voter is either the identity or one of the
     authorized voters, then is_valid_vote will be 1; otherwise it will
     be 0.

     The authority_idx is the index of the authorized voter that needs
     to sign the vote transaction.  If the authorized voter is the
     identity, the authority_idx will be ULONG_MAX.

     TODO: Need to implement "refresh last vote" logic. */

  int   has_vote_txn;
  ulong authority_idx;
  ulong vote_txn_sz;
  uchar vote_txn[ FD_TPU_MTU ];

  /* The latest balance in lamports of our vote account, or ULONG_MAX if
     our account is not found. */

  ulong vote_acct_bal;

  /* Our current on-chain tower with latencies optionally included. */

  ulong              tower_cnt;
  fd_vote_acc_vote_t tower[FD_TOWER_VOTE_MAX];
};
typedef struct fd_tower_slot_done fd_tower_slot_done_t;

struct fd_tower_slot_duplicate {
  fd_gossip_duplicate_shred_t chunks[ FD_EQVOC_CHUNK_CNT ];
};
typedef struct fd_tower_slot_duplicate fd_tower_slot_duplicate_t;

struct fd_tower_slot_ignored {
  ulong slot;
  ulong bank_idx;
};
typedef struct fd_tower_slot_ignored fd_tower_slot_ignored_t;

struct fd_tower_vote_state {
  ulong slot;
  int   is_last_in_slot;
  fd_vote_state_ele_t vs;
};
typedef struct fd_tower_vote_state fd_tower_vote_state_t;

union fd_tower_msg {
  fd_tower_slot_confirmed_t slot_confirmed;
  fd_tower_slot_done_t      slot_done;
  fd_tower_slot_duplicate_t slot_duplicate;
  fd_tower_slot_ignored_t   slot_ignored;
  fd_tower_slot_rooted_t    slot_rooted;
  fd_tower_vote_state_t     vote_state;
};
typedef union fd_tower_msg fd_tower_msg_t;

extern fd_topo_run_tile_t fd_tile_tower;

/* The danger of the circular reliable link between tower and replay is
   that if tower backpressures replay, and happens to have backed-up
   confirmations to publish in after_credit, then tower_out link will
   become full.  If tower doesn't drain from replay_exec in the next
   returnable_frag call, this will cause a credit starvation loop
   between tower and replay, which causes both tiles to stall
   completely.

   Since there's no way to guarantee tower read from a specific link,
   (and no way to guarantee replay will read from a specific link), so
   we just make sure tower_out is large enough that the likelihood that
   the link is close to full and the above scenario happens is low. */

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_h */
