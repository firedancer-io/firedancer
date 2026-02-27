#ifndef HEADER_fd_src_flamenco_gossip_fd_active_set_h
#define HEADER_fd_src_flamenco_gossip_fd_active_set_h

#include "fd_crds.h"
#include "fd_gossip_wsample.h"
#include "../../util/net/fd_net_headers.h"

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

typedef struct fd_active_set_private fd_active_set_t;

#define FD_ACTIVE_SET_ALIGN (64UL)

#define FD_ACTIVE_SET_MAGIC (0xF17EDA2CEA5E1000) /* FIREDANCE ASET V0 */

typedef void (*fd_gossip_send_fn)( void *                 ctx,
                                   fd_stem_context_t *    stem,
                                   uchar const *          data,
                                   ulong                  sz,
                                   fd_ip4_port_t const *  peer_address,
                                   ulong                  now );

struct fd_active_set_metrics {
  ulong message_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];
  ulong message_tx_bytes[ FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT ];

  ulong crds_tx_push[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
  ulong crds_tx_push_bytes[ FD_METRICS_ENUM_CRDS_VALUE_CNT ];
};

typedef struct fd_active_set_metrics fd_active_set_metrics_t;

FD_PROTOTYPES_BEGIN

static inline ulong
fd_active_set_stake_bucket( ulong _stake ) {
  ulong stake = _stake / 1000000000;
  if( FD_UNLIKELY( stake == 0UL ) ) return 0UL;
  ulong bucket = 64UL - (ulong)__builtin_clzl(stake);
  return fd_ulong_min( bucket, 24UL );
}

FD_FN_CONST ulong
fd_active_set_align( void );

FD_FN_CONST ulong
fd_active_set_footprint( void );

void *
fd_active_set_new( void *                shmem,
                   fd_gossip_wsample_t * wsample,
                   fd_crds_t *           crds,
                   fd_rng_t *            rng,
                   uchar const *         identity_pubkey,
                   ulong                 identity_stake,
                   fd_gossip_send_fn     send_fn,
                   void *                send_fn_ctx );

fd_active_set_t *
fd_active_set_join( void * shas );

fd_active_set_metrics_t const *
fd_active_set_metrics( fd_active_set_t const * active_set );

void
fd_active_set_set_identity( fd_active_set_t * active_set,
                            uchar const *     identity_pubkey,
                            ulong             identity_stake );

void
fd_active_set_prune( fd_active_set_t * active_set,
                     uchar const *     push_dest,
                     uchar const *     origin,
                     ulong             origin_stake );

void
fd_active_set_remove_peer( fd_active_set_t * active_set,
                           ulong             ci_idx );

void
fd_active_set_push( fd_active_set_t *   active_set,
                    uchar const *       crds_val,
                    ulong               crds_sz,
                    uchar const *       origin_pubkey,
                    ulong               origin_stake,
                    fd_stem_context_t * stem,
                    long                now,
                    int                 flush_immediately );

void
fd_active_set_advance( fd_active_set_t *   active_set,
                       fd_stem_context_t * stem,
                       long                now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_active_set_h */
