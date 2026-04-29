#ifndef HEADER_fd_src_discof_replay_fd_replay_tile_private_h
#define HEADER_fd_src_discof_replay_fd_replay_tile_private_h

#include "fd_replay_tile.h"
#include "fd_vote_tracker.h"
#include "../../disco/topo/fd_wksp_mon.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/bundle/fd_bundle_crank.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/replay/fd_sched.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/capture/fd_capture_ctx.h"
#include "../../flamenco/genesis/fd_genesis_parse.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/tests/fd_dump_pb.h"
#include <stdio.h>

struct fd_replay_in_link {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_replay_in_link fd_replay_in_link_t;

struct fd_replay_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_replay_out_link fd_replay_out_link_t;

/* fd_block_id_map is a simple map of block-ids to bank indices.  The
   map sits on top of an array of fd_block_id_ele_t.  This serves as a
   translation layer between block ids to bank indices.  The data
   array is indexed by bank index and the latest observed merkle root
   for the bank index is stored in the array.  Once the block id has
   been observed, the entry is keyed by the latest merkle root (aka the
   block id). */

struct fd_block_id_ele {
  fd_hash_t latest_mr;
  uint      latest_fec_idx;
  int       block_id_seen;
  ulong     slot;
  ulong     next_;
};
typedef struct fd_block_id_ele fd_block_id_ele_t;

#define MAP_NAME               fd_block_id_map
#define MAP_ELE_T              fd_block_id_ele_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                latest_mr
#define MAP_NEXT               next_
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

struct fd_replay_tile {
  fd_wksp_t * wksp;

  uint rng_seed;
  fd_rng_t rng[ 1 ];

  fd_accdb_admin_t    accdb_admin[1];
  fd_accdb_user_t     accdb[1];
  fd_progcache_join_t progcache[1];
  fd_wksp_mon_t       progcache_wksp_mon[1];
  fd_wksp_mon_t       accdb_cache_wksp_mon[1];

  fd_txncache_t * txncache;
  fd_store_t *    store;
  fd_banks_t *    banks;
  ulong           frontier_indices[ FD_BANKS_MAX_BANKS ];
  ulong           frontier_cnt;

  /* This flag is 1 If we have seen a vote signature that our node has
     sent out get rooted at least one time.  The value is 0 otherwise.
     We can't become leader and pack blocks until this flag has been
     set.  This parallels the Agave 'has_new_vote_been_rooted'. */
  int identity_vote_rooted;
  int wait_for_vote_to_start_leader;

  /* wfs_enabled is 1 if the validator is booted in
     wait_for_supermajority mode. In this mode replay (and, by extension,
     downstream consumers) is not allowed to make progress until 80% of
     the cluster has published their ContactInfo in Gossip with a
     shred version matching expected_shred_version. When this happens,
     wfs_complete will be set to 1. */
  int   wfs_enabled;
  int   wfs_complete;

  fd_hash_t expected_bank_hash;

  ulong            reasm_seed;
  fd_reasm_t     * reasm;
  fd_reasm_fec_t * reasm_evicted;       /* evicted FEC by reasm_insert must be stored in returnable_frag, and then drained in after_credit */

  fd_sched_t * sched;
  ulong        in_cnt;
  ulong        execrp_idle_cnt;

  ulong                vote_tracker_seed;
  fd_vote_tracker_t *  vote_tracker;

  int          has_genesis_hash;
  char         genesis_path[ PATH_MAX ];
  fd_hash_t    genesis_hash[1];
  fd_genesis_t genesis[1];
  ulong        cluster_type;

  int   has_genesis_timestamp;
  ulong genesis_timestamp;
  int   has_expected_genesis_timestamp;
  ulong expected_genesis_timestamp;

#define FD_REPLAY_HARD_FORKS_MAX (64UL)
  ulong hard_forks_cnt;
  ulong hard_forks[ FD_REPLAY_HARD_FORKS_MAX ];
  ulong hard_forks_cnts[ FD_REPLAY_HARD_FORKS_MAX ];

  ushort expected_shred_version;
  ushort ipecho_shred_version;

  /* A note on publishing ...

     The watermarks are used to publish our fork-aware structures.  For
     example, store, banks, and txncache need to be published to release
     resources occupied by rooted or dead blocks.  In general,
     publishing has the effect of pruning forks in those structures,
     indicating that it is ok to release the memory being occupied by
     the blocks on said forks.  Tower is responsible for informing us of
     the latest block on the consensus rooted fork.  As soon as we can,
     we should move the published root as close as possible to the
     latest consensus root, publishing/pruning everything on the fork
     tree along the way.  That is, all the blocks that directly descend
     from the current published root (inclusive) to the new published
     root (exclusive) on the rooted fork, as well as all the minority
     forks that branch from said blocks.

     Ideally, we'd move the published root to the consensus root
     immediately upon receiving a new consensus root.  However, that's
     not always safe to do.  One thing we need to be careful about is
     making sure that there are no more users/consumers of
     soon-to-be-pruned blocks, lest a use-after-free occurs.  This can
     be done by using a reference counter for each block.  Any
     concurrent activity, such as transaction execution in the exec
     tiles, should retain a refcnt on the block for as
     long as it needs access to the shared fork-aware structures related
     to that block.  Eventually, refcnt on a given block will drop down
     to 0 as the block either finishes replaying or gets marked as dead,
     and any other tile that has retained a refcnt on the block releases
     it.  At that point, it becomes a candidate for pruning.  The key to
     safe publishing then becomes figuring out how far we could advance
     the published root, such that every minority fork branching off of
     blocks in between the current published root (inclusive) and the
     new published root (exclusive) is safe to be pruned.  This is a
     straightforward tree traversal, where if a block B on the rooted
     fork has refcnt 0, and all minority forks branching off of B also
     have refcnt 0, then B is safe to be pruned.  We advance the
     published root to the farthest consecutively prunable block on the
     rooted fork.  Note that reasm presents the replay tile with a clean
     view of the world where every block is chained off of a parent
     block.  So there are no orpahned/dangling tree nodes to worry
     about.  The world is a nice single tree as far as replay is
     concerned.

     In the following fork tree, every node is a block and the number in
     parentheses is the refcnt on the block.  The chain marked with
     double slashes is the rooted fork.  Suppose the published root is
     at block P, and consensus root is at block T.  We can't publish
     past block P because Q has refcnt 1.


          P(0)
        /    \\
      Q(1)    A(0)
            / ||  \
        X(0) B(0)  C(0)
       /      || \
      Y(0)   M(0) R(0)
            / ||   /  \
        D(2) T(0) J(0) L(0)
              ||
              ..
              ..
              ..
              ||
      blocks we might be actively replaying


     When refcnt on Q drops to 0, we would be able to advance the
     published root to block M, because blocks P, A, and B, as well as
     all subtrees branching off of them, have refcnt 0, and therefore
     can be pruned.  Block M itself cannot be pruned yet because its
     child block D has refcnt 2.  After publishing/pruning, the fork
     tree would be:


             M(0)
            / ||
        D(2) T(0)
              ||
              ..
              ..
              ..
              ||
      blocks we might be actively replaying


     As a result, the shared fork-aware structures can free resources
     for blocks P, A, B, and all subtrees branching off of them.

     For the reference counting part, the replay tile is the sole entity
     that can update the refcnt.  This ensures that all refcnt increment
     and decrement attempts are serialized at the replay tile, and that
     there are no racy resurrection of a soon-to-be-pruned block.  If a
     refcnt increment request arrives after a block has been pruned,
     replay simply rejects the request.

     A note on the implementation of the above ...

     Upon receiving a new consensus root, we descend down the rooted
     fork from the current published root to the new consensus root.  On
     each node/block of the rooted fork, we do a summation of the refcnt
     on the block and all the minority fork blocks branching from the
     block.  If the summation is 0, the block is safe for pruning.  We
     advance the published root to the far end of the consecutive run of
     0 refcnt sums originating from the current published root.  On our
     descent down the minority forks, we also mark any block that hasn't
     finished replaying as dead, so we don't waste time executing them.
     No more transactions shall be dispatched for execution from dead
     blocks.

     Blocks start out with a refcnt of 0.  Other tiles may send a
     request to the replay tile for a reference on a block.  The
     transaction dispatcher is another source of refcnt updates.  On
     every dispatch of a transaction for block B, we increment the
     refcnt for B.  And on every transaction finalization, we decrement
     the refcnt for B.  This means that whenever the refcnt on a block
     is 0, there is no more reference on that block from the execution
     pipeline.  While it might be tempting to simply increment the
     refcnt once when we start replaying a block, and decrement the
     refcnt once when we finish a block, this more fine-grained refcnt
     update strategy allows for aborting and potentially immediate
     pruning of blocks under interleaved block replay.  Upon receiving a
     new consensus root, we can simply look at the refcnt on minority
     fork blocks, and a refcnt of 0 would imply that the block is safe
     for pruning, even if we haven't finished replaying it.  Without the
     fine-grained refcnt, we would need to first stop dispatching from
     the aborted block, and then wait for a full drain of the execution
     pipeline to know for sure that there are no more in-flight
     transactions executing on the aborted block.  Note that this will
     allow the refcnt on any block to transiently drop down to 0.  We
     will not mistakenly prune an actively replaying block, aka a leaf
     node, that is chaining off of the rooted fork, because the
     consensus root is always an ancestor of the actively replaying tip.
     */
  fd_hash_t consensus_root;          /* The most recent block to have reached max lockout in the tower. */
  ulong     consensus_root_slot;     /* slot number of the above. */
  ulong     consensus_root_bank_idx; /* bank index of the above. */
  ulong     published_root_slot;     /* slot number of the published root. */
  ulong     published_root_bank_idx; /* bank index of the published root. */

  /* Randomly generated block id for the initial genesis/snapshot slot.
     To be replaced with block id in the snapshot manifest when SIMD-333
     is activated. */

  fd_hash_t initial_block_id;

  /* We need to maintain a tile-local mapping of block-ids to bank index
     and vice versa.  This translation layer is needed for conversion
     since tower operates on block-ids and downstream consumers of FEC
     sets operate on bank indices.  This mapping must happen both ways:
     1. tower sends us block ids and we must map them to bank indices.
     2. when a block is completed, we must map the bank index to a block
        id to send a slot complete message to tower. */
  ulong               block_id_len;
  fd_block_id_ele_t * block_id_arr;
  ulong               block_id_map_seed;
  fd_block_id_map_t * block_id_map;

  /* Capture-related configs */
  fd_capture_ctx_t *     capture_ctx;
  FILE *                 capture_file;
  fd_capture_link_buf_t  cap_repl_out[1];

  /* Protobuf dumping context for debugging runtime execution and
     collecting seed corpora. */
  fd_dump_proto_ctx_t * dump_proto_ctx;

  /* Whether the runtime has been booted either from snapshot loading
     or from genesis. */
  int is_booted;

  /* Buffer to store vote towers that need to be published to the Tower
     tile. */

  fd_multi_epoch_leaders_t * mleaders;

  int larger_max_cost_per_block;

  /* When we transition to becoming leader, we can only unbecome the
     leader if we have received a block id from the FEC reassembler, and
     a message from PoH that the leader slot has ended.  After both of
     these conditions are met, then we are free to unbecome the leader.
  */
  uint        is_leader : 1;
  uint        supports_leader : 1;
  int         recv_poh;
  ulong       next_leader_slot;
  long        next_leader_tickcount;
  ulong       highwater_leader_slot;
  ulong       reset_slot;
  fd_bank_t * reset_bank;
  fd_hash_t   reset_block_id;
  long        reset_timestamp_nanos;
  double      slot_duration_nanos;
  double      slot_duration_ticks;
  fd_bank_t * leader_bank;

  fd_pubkey_t      identity_pubkey[1];
  ulong            identity_idx;

  fd_keyswitch_t * keyswitch;
  int              halt_leader;

  ulong  resolv_tile_cnt;

  int in_kind[ 128 ];
  fd_replay_in_link_t in[ 128 ];

  fd_replay_out_link_t exec_out[ 1 ];

  fd_replay_out_link_t replay_out[1];

  fd_replay_out_link_t epoch_out[1];

  /* The rpc tile needs to occasionally own a reference to a live bank.
     Replay needs to know if the rpc as a consumer is enabled so it can
     increment the bank's refcnt before publishing bank_idx. */
  int rpc_enabled;

  /* For dumping blocks to protobuf. For backtest only. */
  fd_block_dump_ctx_t * block_dump_ctx;

  /* We need a few pieces of information to compute the right addresses
     for bundle crank information that we need to send to pack. */
  struct {
    int                   enabled;
    fd_pubkey_t           vote_account;
    fd_bundle_crank_gen_t gen[1];
  } bundle;

  struct {
    ulong      store_query_acquire;
    ulong      store_query_release;
    fd_histf_t store_query_wait[1];
    fd_histf_t store_query_work[1];
    ulong      store_query_cnt;
    ulong      store_query_missing_cnt;
    ulong      store_query_mr;
    ulong      store_query_missing_mr;

    ulong slots_total;
    ulong transactions_total;

    ulong reasm_latest_slot;
    ulong reasm_latest_fec_idx;

    ulong sched_full;
    ulong reasm_empty;
    ulong leader_bid_wait;
    ulong banks_full;
    ulong storage_root_behind;

    fd_histf_t root_slot_dur[1];
    fd_histf_t root_account_dur[1];
  } metrics;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];

  ulong                runtime_stack_seed;
  fd_runtime_stack_t * runtime_stack;
};

typedef struct fd_replay_tile fd_replay_tile_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_private_h */
