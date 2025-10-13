#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_wpeer_sampler_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_wpeer_sampler_h

#include "../../util/fd_util.h"

/* wpeer_sampler provides a set of APIs to maintain a weighted sampler
   with the ability to change weights dynamically on a runtime-bounded
   element set. The sampler is designed to be used for sampling peers
   in various parts of the gossip protocol. Users supply weights/score
   updates in wpeer_sampler_upd and sample with wpeer_sampler_sample.

   The sampler works in terms of indices into an array of peers. The
   user is responsible for maintaining a mapping between peers and
   indices. The sampler does not store any information about the peers
   themselves. fd_crds provides a set of APIs to track a peer's contact
   info with an index to the contact info sidetable. These are provided
   by fd_crds_ci_change_fn callbacks, with an API to lookup the
   corresponding Contact Info.

   Why not use fd_wsample? The peer population constantly changes
   throughout the epoch, as nodes enter, leave, or become
   (un)responsive in the cluster. The fd_wsample APIs (currenlty)
   do not provide the ability to change individual peer weights without
   clearing the sampler and recalculating scores. */

#define SAMPLE_IDX_SENTINEL ULONG_MAX

struct wpeer_sampler_private;
typedef struct wpeer_sampler_private wpeer_sampler_t;

FD_FN_CONST static inline ulong
wpeer_sampler_align( void ) {
  return 8UL;
}

FD_FN_CONST ulong
wpeer_sampler_footprint( ulong max_peers );

void *
wpeer_sampler_new( void * shmem, ulong  max_peers );

wpeer_sampler_t *
wpeer_sampler_join( void * shmem );

/* wpeer_sampler_sample returns the index of the entry sampled
   by the weighted sampler. Does not sample entries with 0 weight.  */
ulong
wpeer_sampler_sample( wpeer_sampler_t const * ps,
                      fd_rng_t *              rng );

/* wpeer_sampler_upd updates the weight/score of the entry at index idx
   to weight. idx must be in [0, max_peers). weight can be 0, which
   effectively disables the entry in the sampler population. */
int
wpeer_sampler_upd( wpeer_sampler_t * ps,
                   ulong             weight,
                   ulong             idx );


#endif
