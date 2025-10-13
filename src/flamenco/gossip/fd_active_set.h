#ifndef HEADER_fd_src_flamenco_gossip_fd_active_set_h
#define HEADER_fd_src_flamenco_gossip_fd_active_set_h

#include "fd_gossip_txbuild.h"
#include "crds/fd_crds.h"

/* fd_active_set provides APIs for tracking the active set of nodes we
   should push messages to in a gossip network. It is tightly coupled
   with the contact info sidetable in fd_crds, making use of the
   index into the sidetable as a stable identifier for peers.

   In the Solana gossip protocol, each node selects a random set of up
   to 300 peers to send messages to, and then rotates one of the nodes
   out for a new, randomly selected one every so often.

   This is simple enough: just keep a list of the peer pubkeys, and
   occasionally replace one?

   There's three complications:

    (1) We want to select peers with a good distribution of stakes, so
        that we don't end up sending to a lot of low-stake peers if
        someone pollutes the gossip table with junk.

    (2) Peers sometimes request that we don't forward messages from
        other originating (origin) nodes to them, because they already
        have a lot of paths from that node.  This is called a prune.

    (3) We need to gracefully update the active set if a peer either
        changes its stake or enters/leaves the network.

   Complication (1) is handled by keeping a list of 12 peers for each
   of 25 buckets of stakes.  These buckets are rotated with a weighted
   shuffle specific to the stake bucket. Note that a single peer can
   appear in multiple buckets, but each bucket has a unique set of
   peers.

   Problem (2) is solved by keeping a bloom filter for each of the
   12 peers in each bucket.  The bloom filter is used to track which
   origins the peer has pruned.

   A set of peer update APIs are provided to handle the peer's changes
   described in (3). The supplied index maps to the peer's entry in
   contact info sidetable in fd_crds. */

#define FD_ACTIVE_SET_STAKE_BUCKETS    (25UL)
#define FD_ACTIVE_SET_PEERS_PER_BUCKET (12UL)
#define FD_ACTIVE_SET_MAX_PEERS        (FD_ACTIVE_SET_STAKE_BUCKETS*FD_ACTIVE_SET_PEERS_PER_BUCKET) /* 300 */

/* fd_active_set_push_state holds the state for a particular
   (bucket, peer) pair that is in rotation. */
struct fd_active_set_push_state {
   fd_gossip_txbuild_t * txbuild;
   ulong                 crds_idx; /* index into the CRDS contact info sidetable. */
};

typedef struct fd_active_set_push_state fd_active_set_push_state_t;


#define FD_ACTIVE_SET_ALIGN     (128UL)

struct fd_active_set_private;
typedef struct fd_active_set_private fd_active_set_t;

#define FD_ACTIVE_SET_MAGIC (0xF17EDA2CEA5E1000) /* FIREDANCE ASET V0 */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_active_set_align( void );

FD_FN_CONST ulong
fd_active_set_footprint( void );

void *
fd_active_set_new( void *     shmem,
                   fd_rng_t * rng );

fd_active_set_t *
fd_active_set_join( void * shas );

/* fd_active_set_nodes retrieves the list of nodes that we should push
   messages from the origin to.  The list will not include peers that
   have pruned the origin, except if ignore_prunes_if_peer_is_origin
   is non-zero, in which case the list will include a peer if its pubkey
   matches the origin pubkey.

   Up to 12 peer push states will be returned in out_push_states. The
   states are expected to be used (for appending) immediately,
   and the user is expected to flush and reset (with
   fd_gossip_txbuild_init) the push states if they are too full to fit
   a new CRDS value. The states returned in out_push_states are only
   valid for the current active set and should not be used after a call
   to any of the fd_active_set APIs below. */

ulong
fd_active_set_nodes( fd_active_set_t *          active_set,
                     uchar const *              identity_pubkey,
                     ulong                      identity_stake,
                     uchar const *              origin,
                     ulong                      origin_stake,
                     int                        ignore_prunes_if_peer_is_origin,
                     long                       now,
                     fd_active_set_push_state_t out_push_states[ static FD_ACTIVE_SET_PEERS_PER_BUCKET ] );

/* fd_active_set_prune adds origin to a peer's pruned bloom filter. The
   prune record persists for the time in which the peer is in the active
   set. */

void
fd_active_set_prune( fd_active_set_t * active_set,
                     uchar const *     peer,
                     uchar const *     origin,
                     ulong             origin_stake,
                     uchar const *     identity_pubkey,
                     ulong             identity_stake );

/* fd_active_set_rotate chooses a random active bucket entry to
   swap/introduce a peer into. The peer is sampled from a distribution
   (provided by crds) specific to the active set bucket. If there are
   no peers available to sample from, the function is a no-op.

   If a peer is swapped out of the bucket, its push state
   will be supplied in out_maybe_flush. out_maybe_flush->txbuild is NULL
   otherwise. The push state is valid until the next call to any
   fd_active_set API. If a state is supplied, the user is expected to
   flush and reset (with fd_gossip_txbuild_init) the state immediately.
   */

void
fd_active_set_rotate( fd_active_set_t *            active_set,
                      fd_crds_t *                  crds,
                      long                         now,
                      fd_active_set_push_state_t * out_maybe_flush );

/* fd_active_set_flush_stale_advance checks the least recently hit push
   state in the active set and determines if it should be flushed. A
   push state is considered stale if its last-updated timestamp is older
   than stale_if_before.

   If the least recently hit push state is stale, it is is extracted
   into maybe_flush, its timestamp is refreshed to now, and it is moved
   to the back of the LRU queue. The caller is expected to flush and
   reset (with fd_gossip_txbuild_init) the push state immediately.

   This function processes at most one push state per call, allowing
   the caller to interleave flushing with other operations. Since push
   states are ordered by last_hit timestamp, if the least recently hit
   push state is not stale, no other states will be stale either.

   Returns 1 if a stale state was found and maybe_flush contains valid
   state to flush. Returns 0 if no stale states exist or the active
   set is empty. The push state in maybe_flush is valid until the next
   call to any fd_active_set API. */

int
fd_active_set_flush_stale_advance( fd_active_set_t *            active_set,
                                   long                         stale_if_before,
                                   long                         now,
                                   fd_active_set_push_state_t * maybe_flush );

/* The fd_active_set_peer_{insert, remove, update_stake} APIs track
   the relevant changes to the fd_crds contact info sidetable. crds_idx
   refers to the index to the peer in the sidetable, and should be
   retrieved by the callback API provided in fd_crds. */

void
fd_active_set_peer_insert( fd_active_set_t * active_set, ulong crds_idx, ulong stake );

/* When a peer is removed from the active set entirely,
   fd_active_set_peer_remove returns the number of active push states
   (across all buckets) belonging to the evicted peer. These states are
   populated in out_evicted_states, and are only valid until the next
   call to any fd_active_set API.

   The user is expected to reset these push states
   (with fd_gossip_txbuild_init). Flushing these states is optional. */
ulong
fd_active_set_peer_remove( fd_active_set_t *          active_set,
                           ulong                      crds_idx,
                           fd_active_set_push_state_t out_evicted_states[ static FD_ACTIVE_SET_STAKE_BUCKETS ] );

void
fd_active_set_peer_update_stake( fd_active_set_t * active_set, ulong crds_idx, ulong new_stake );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_active_set_h */
