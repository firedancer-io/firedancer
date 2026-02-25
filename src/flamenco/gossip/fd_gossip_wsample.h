#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_wsample_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_wsample_h

#include "../../util/rng/fd_rng.h"

struct fd_gossip_wsample_private;
typedef struct fd_gossip_wsample_private fd_gossip_wsample_t;

FD_FN_CONST ulong
fd_gossip_wsample_align( void );

FD_FN_CONST ulong
fd_gossip_wsample_footprint( ulong max_peers );

void *
fd_gossip_wsample_new( void *     shmem,
                       fd_rng_t * rng,
                       ulong      max_peers );

fd_gossip_wsample_t *
fd_gossip_wsample_join( void * shwsample );

void
fd_gossip_wsample_add( fd_gossip_wsample_t * sampler,
                       ulong                 idx,
                       ulong                 stake,
                       int                   active );

void
fd_gossip_wsample_remove( fd_gossip_wsample_t * sampler,
                          ulong                 idx );

/* fd_gossip_wsample_self_stake sets our own node's stake in the
   sampler.  In Agave, each peer's pull-request weight is computed
   using min(peer_stake, self_stake).  This must be called (and kept
   up-to-date, e.g. at epoch boundaries) so that the cap is applied
   correctly.  If self_stake is 0 (the default), all peers are treated
   as zero-stake for PR weight purposes. */

void
fd_gossip_wsample_self_stake( fd_gossip_wsample_t * sampler,
                              ulong                 self_stake );

/* fd_gossip_wsample_stake updates the stake of a peer in the sampler.
   This should be used to update the stake of a peer when we have new
   information about its stake, such as from a new contact info message. */

void
fd_gossip_wsample_stake( fd_gossip_wsample_t * sampler,
                         ulong                 idx,
                         ulong                 stake );

/* fd_gossip_wsample_fresh marks a peer as fresh or not fresh in the
   sampler.  In Agave, unfresh (stale >60s) unstaked peers are excluded
   entirely from pull request sampling, while stale staked peers get a
   1/16 random chance of inclusion (eclipse attack mitigation).  In this
   persistent sampler we approximate that as: unfresh unstaked peers get
   weight 0, unfresh staked peers get full_weight/16.  Peers are assumed
   fresh when first added, so this should only be called to toggle
   freshness after adding a peer. */

void
fd_gossip_wsample_fresh( fd_gossip_wsample_t * sampler,
                         ulong                 idx,
                         int                   fresh );

/* fd_gossip_wsample_active marks a peer as active or inactive in the
   sampler.  Active peers are eligible to be sampled; inactive peers are
   not.  This should be used to mark a peer as inactive when we have
   evidence that the peer is not responsive, and mark it active again if
   we later have evidence that it is responsive again. */

void
fd_gossip_wsample_active( fd_gossip_wsample_t * sampler,
                          ulong                 idx,
                          int                   active );

/* fd_gossip_wsample_sample_pull_request samples a peer index for
   sending a pull request.  Returns ULONG_MAX if no peers are available
   to sample.  This should be used for pull requests, which sample from
   all peers, and not for bucket sampling, which should use
   fd_gossip_wsample_sample_remove_bucket.  Peers sampled with
   fd_gossip_wsample_sample_pull_request are not removed from the
   sampler, so they can be sampled again immediately by random chance. */

ulong
fd_gossip_wsample_sample_pull_request( fd_gossip_wsample_t * sampler );

/* fd_gossip_wsample_sample_remove_bucket samples a peer from the given
   bucket, returning the index of the sampled peer, or ULONG_MAX if the
   bucket is empty.  The sampled peer is removed from this bucket in the
   sampler (but not removed overall) and must be added back with
   fd_gossip_wsample_add_bucket to be sampleable in that bucket again. */

ulong
fd_gossip_wsample_sample_remove_bucket( fd_gossip_wsample_t * sampler,
                                        ulong                 bucket );

/* fd_gossip_wsample_add_bucket adds a peer to the given bucket in the
   sampler.  This should be used to add back a peer that was previously
   sampled with fd_gossip_wsample_sample_remove_bucket.  idx is the
   index of the peer to add back, which is the value previously returned
   by fd_gossip_wsample_sample_remove_bucket. */

void
fd_gossip_wsample_add_bucket( fd_gossip_wsample_t * sampler,
                              ulong                 bucket,
                              ulong                 idx );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_wsample_h */
