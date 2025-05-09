#ifndef HEADER_fd_src_flamenco_gossip_fd_active_set_h
#define HEADER_fd_src_flamenco_gossip_fd_active_set_h

#include "fd_bloom.h"

/* fd_active_set provides APIs for tracking the active set of nodes we
   should push messages to in a gossip network.

   In the Solana gossip protocol, each node selects a random set of up
   to 300 peers to send messages to, and then rotates one of the nodes
   out for a new, randomly selected one every so often.

   This is simple enough: just keep a list of the peer pubkeys, and
   occasionally replace one?

   There's two complications:

    (1) We want to select peers with a good distribution of stakes, so
        that we don't end up sending to a lot of low-stake peers if
        someone pollutes the gossip table with junk.

    (2) Peers sometimes request that we don't forward messages from
        other originating (origin) nodes to them, because they already
        have a lot of paths from that node.  This is called a prune.
   
   Complication (1) is handled by keeping a list of the top 12 peers
   (sorted by stake) for each of 25 buckets of stakes.  These buckets
   are all rotated together.

   And problem (2) is solved by keeping a bloom filter for each of the
   12 peers in each bucket.  The bloom filter is used to track which
   origins the peer has pruned. */

struct fd_active_set_peer {
  uchar        pubkey[ 32UL ];
  fd_bloom_t * bloom;
};

typedef struct fd_active_set_peer fd_active_set_peer_t;

struct fd_active_set_entry {
  ulong                nodes_idx;
  ulong                nodes_len;
  fd_active_set_peer_t nodes[ 12UL ][ 1UL ];
};

typedef struct fd_active_set_entry fd_active_set_entry_t;

#define FD_ACTIVE_SET_ALIGN     (64UL)

struct __attribute__((aligned(FD_ACTIVE_SET_ALIGN))) fd_active_set_private {
  fd_active_set_entry_t entries[ 25UL ][ 1UL ];

  fd_rng_t * rng;

  ulong magic; /* ==FD_ACTIVE_SET_MAGIC */
};

typedef struct fd_active_set_private fd_active_set_t;

#define FD_ACTIVE_SET_FOOTPRINT (sizeof(fd_active_set_t))

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
   
   Up to 12 peer nodes will be returned in out_nodes.  The values
   returned in out_nodes are an internal peer index of the active set
   and should not be used for anything other than calling
   fd_active_set_node_pubkey to get the pubkey of the peer.  The
   peer index is only valid for the current active set and should not be
   used after a call to fd_active_set_rotate or fd_active_set_prune. */

ulong
fd_active_set_nodes( fd_active_set_t * active_set,
                     uchar const *     identity_pubkey,
                     ulong             identity_stake,
                     uchar const *     origin,
                     ulong             origin_stake,
                     int               ignore_prunes_if_peer_is_origin,
                     ulong             out_nodes[ static 12UL ] );

uchar const *
fd_active_set_node_pubkey( fd_active_set_t * active_set,
                           ulong             peer_idx );

void
fd_active_set_prune( fd_active_set_t * active_set,
                     uchar const *     identity_pubkey,
                     ulong             identity_stake,
                     uchar const *     peer,
                     uchar const *     destination,
                     uchar const *     origin,
                     ulong             origin_stake );

void
fd_active_set_rotate( fd_active_set_t *     active_set,
                      ulong                 cluster_size,
                      uchar const * const * nodes,
                      ulong const *         stakes,
                      ulong                 nodes_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_active_set_h */
