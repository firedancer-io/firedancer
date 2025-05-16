#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../../util/rng/fd_rng.h"
#include "../../util/net/fd_net_headers.h"
#include "fd_gossip_types.h"
#include "fd_gossip_out.h"
#include "fd_gossip_metrics.h"

/* TODO: When we get a pull request, respond with ContactInfos first if
   we have any available that are responsive. */

/* The Solana gossip protocol is used so that distributed nodes can
   share key-value pairs and reach an eventually consistent consensus on
   what's in the key-value store.

   It is peer to peer, and proceeds with these key pieces:

    - To join the cluster, a node must first contact a known node
      (an entrypoint) and register itself, by sending its own contact
      information key-value pair.  Contact information is the UDP
      address and port.

    - The cluster will then agree on that key-value pair, and start
      broadcasting updates to the node.

    - Each node must periodically send new messages it has received to
      a (somewhat) random selection of peers (referred to as the active
      set).

    - In addition, each node can periodically send a "pull request" to
      a random selection of peers, asking them to send any messages
      they have that the node does not.  This is used to ensure that
      nodes are eventually consistent in case they miss some pushed
      messages.  Bloom filters are used to track which messages have
      been received, and to avoid sending duplicates.

    - Each node can also send prune messages to peers, asking them
      to stop forwarding (pushing) messages from a particular origin.
      This is used to avoid receiving too many duplicate messages from
      the same origin.

    - Nodes with stake are always considered part of the network, but
      low staked nodes need to maintain a connection by responding to
      ping messages.  These pings are to prevent DDoS attacks which
      reflect off gossip nodes.

   Other than this, everything else is implementation details.  For
   specifics on the network and wire protocol, see https://github.com/eigerco/solana-spec/blob/main/gossip-protocol-spec.md
   and for more details on the Agave implementation, see https://github.com/eigerco/solana-spec/blob/main/implementation-details.md

   The Solana gossip protocol is heavily based on Plum Tree, see
   https://www.dpss.inesc-id.pt/~ler/reports/srds07.pdf for details. */

struct fd_gossip_private;
typedef struct fd_gossip_private fd_gossip_t;



typedef void (*fd_gossip_send_fn)( void *                 ctx,
                                   fd_stem_context_t *    stem,
                                   uchar const *          data,
                                   ulong                  sz,
                                   fd_ip4_port_t const *  peer_address,
                                   ulong                  now );

typedef void (*fd_gossip_sign_fn)( void *         ctx,
                                   uchar const *  data,
                                   ulong          sz,
                                   int            sign_type,
                                   uchar *        out_signature );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gossip_align( void );

FD_FN_CONST ulong
fd_gossip_footprint( ulong max_values );

void *
fd_gossip_new( void *                    shmem,
               fd_rng_t *                rng,
               ulong                     max_values,
               ulong                     entrypoints_cnt,
               fd_ip4_port_t const *     entrypoints,
               fd_contact_info_t const * my_contact_info,
               long                      now,
               fd_gossip_send_fn         send_fn,
               void *                    send_ctx,
               fd_gossip_sign_fn         sign_fn,
               void *                    sign_ctx,
               fd_gossip_out_ctx_t *     gossip_update_out,
               fd_gossip_out_ctx_t *     gossip_net_out );

fd_gossip_t *
fd_gossip_join( void * shgossip );

fd_gossip_metrics_t const *
fd_gossip_metrics( fd_gossip_t const * gossip );

/* fd_gossip stores the node's contact info for various purposes:

      - The pubkey specified in contact_info will serve as the
        identity key, used in various checks of the rx path.

      - If the shred version specified in the contact_info is non-zero,
        it will be used to determine whether to accept or drop incoming
        messages from peers.

      - The contact info will be periodically gossiped to peers via
        push messages.

        - contact_info should have its wallclock correctly updated
          in order to avoid timeouts on peers

          TODO: update wallclock ourselves? */
void
fd_gossip_set_my_contact_info( fd_gossip_t *             gossip,
                               fd_contact_info_t const * contact_info,
                               long                      now );

void
fd_gossip_stakes_update( fd_gossip_t *             gossip,
                         fd_stake_weight_t const * stake_weights,
                         ulong                     stake_weights_cnt );

/* fd_gossip_advance advances the gossip protocol to the provided time,
   performing any necessary updates and actions along the way.  The
   actions performed include,

   Advancing gossip forward will cause a variety of things to happen,

    - Pings will be sent to any peer nodes that are not validated, or
      need their token refreshed.

    - Old entries in the CRDS will be expired.

    - Partially constructed push messages may need to be periodically
      flushed.

    - A new pull request will be periodically sent out to a random peer,
      to request any messages we might be missing.

    - Contact info messages will be periodically sent out to a random
      selection of peers, to inform them of our current contact info.

    - The active set of peers that we are pushing to will be
      periodically rotated, with one new peer entering and one old peer
      leaving, based on stake weights.


   Only actions which are necessary and useful will be performed, and
   the function is idempotent and fast otherwise.  advance should be
   called as often as possible. */

void
fd_gossip_advance( fd_gossip_t *       gossip,
                   long                now,
                   fd_stem_context_t * stem );

/* fd_gossip_rx handles an incoming packet received on the gossip socket
   from the network.  It is expected that the packet is a UDP packet but
   otherwise no assumptions are made about the contents of the packet,
   in particular it might be malformed, corrupted, malicious, and so on.

   now is the current time in nanoseconds, and is used to determine
   whether the packet is stale or not, and to update the internal state
   of the gossip protocol.

   Receiving a packet might cause response packets to need to be sent
   back to the gossip network.  The response packets are queued for
   later sending.  The caller is responsible for sending the response
   packets by calling fd_gossip_tx().

   Returns 0 on success, and an error code on failure.  Receive side
   errors are entirely recoverable and do not interrupt the operation of
   the gossip protocol.  It is highly advised to terminate the
   application on a DUPLICATE_INSTANCE error to prevent slashable
   activity. */

int
fd_gossip_rx( fd_gossip_t *       gossip,
              uchar const *       data,
              ulong               data_sz,
              long                now,
              fd_stem_context_t * stem );

int
fd_gossip_push_vote( fd_gossip_t *       gossip,
                     uchar const *       txn,
                     ulong               txn_sz,
                     fd_stem_context_t * stem,
                     long                now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
