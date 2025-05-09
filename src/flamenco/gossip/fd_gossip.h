#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../../util/rng/fd_rng.h"
#include "../../util/net/fd_net_headers.h"

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

struct fd_gossip_metrics {
  ulong table_size;
  ulong table_expired;
  ulong table_evicted;

  ulong purged_size;

  ulong failed_size;
};

typedef struct fd_gossip_metrics fd_gossip_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gossip_align( void );

FD_FN_CONST ulong
fd_gossip_footprint( ulong max_values );

void *
fd_gossip_new( void *                shmem,
               fd_rng_t *            rng,
               ulong                 max_values,
               int                   has_expected_shred_version,
               ushort                expected_shred_version,
               ulong                 entrypoints_cnt,
               fd_ip4_port_t const * entrypoints,
               uchar const *         identity_pubkey );

fd_gossip_t *
fd_gossip_join( void * shgossip );

fd_gossip_metrics_t const *
fd_gossip_metrics( fd_gossip_t const * gossip );

void
fd_gossip_set_expected_shred_version( fd_gossip_t * gossip,
                                      int           has_expected_shred_version,
                                      ushort        expected_shred_version );

void
fd_gossip_set_identity( fd_gossip_t * gossip,
                        uchar const * identity_pubkey );

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
fd_gossip_advance( fd_gossip_t * gossip,
                   long          now );

/* fd_gossip_rx handles an incoming packet received on the gossip socket
   from the network.  It is expected that the packet is a UDP packet but
   otherwise no assumptions are made about the contents of the packet,
   in particular it might be malformed, corrupted, malicious, and so on.

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
fd_gossip_rx( fd_gossip_t * gossip,
              uchar const * data,
              ulong         data_sz,
              long          now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
