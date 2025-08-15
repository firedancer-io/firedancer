#ifndef HEADER_fd_src_flamenco_gossip_fd_ping_tracker_h
#define HEADER_fd_src_flamenco_gossip_fd_ping_tracker_h

/* The gossip network amplifies inbound traffic.  For example, a node
   can send us a small pull request, with an empty bloom filter and then
   get back a very large set of pull responses.

   This is not good because an attacker can use it as a reflection
   vector for a DDoS attack.  To prevent this, we enforce a rule that we
   can only send data to peers that have responded to a ping request.

   The fd_ping_tracker maintains a metadata about the peers available to
   ping, who has been pinged, and who has responded, so that we can
   quickly determine before sending a message if we should send it or
   not.

   Any peer which has tried to send us a gossip message within the last
   two minutes is eligible to be pinged, except nodes with at least one
   SOL of stake which are exempt from ping requirements.

   Once a peer has been pinged, we wait up to twenty seconds for a
   response before trying again.  We repeatedly retry pinging the peer
   until the peer responds, or their most recent message becomes older
   than two minutes.

   Once a peer is validated by responding to a ping with a valid pong,
   it is considered valid for 20 minutes.  After 18 minutes, we will
   begin pinging the peer again, every twenty seconds, to refresh the
   peer. */

#include "../../util/rng/fd_rng.h"
#include "../../util/net/fd_net_headers.h"

#define FD_PING_TRACKER_ALIGN (128UL)

#define FD_PING_TRACKER_MAGIC (0xF17EDA2CE0113100) /* FIREDANCE PINGT V0 */

#define FD_PING_TRACKER_MAX (65536UL)

struct fd_ping_tracker_private;
typedef struct fd_ping_tracker_private fd_ping_tracker_t;

struct fd_ping_tracker_metrics {
  ulong unpinged_cnt;
  ulong invalid_cnt;
  ulong valid_cnt;
  ulong refreshing_cnt;

  ulong peers_evicted;

  ulong tracked_cnt;
  ulong stake_changed_cnt;
  ulong address_changed_cnt;

  ulong pong_result[ 6UL ];
};

typedef struct fd_ping_tracker_metrics fd_ping_tracker_metrics_t;

#define FD_PING_TRACKER_CHANGE_TYPE_ACTIVE          (0)
#define FD_PING_TRACKER_CHANGE_TYPE_INACTIVE        (1)
#define FD_PING_TRACKER_CHANGE_TYPE_INACTIVE_STAKED (2)

typedef void (*fd_ping_tracker_change_fn)( void *        ctx,
                                           uchar const * peer_pubkey,
                                           fd_ip4_port_t peer_address,
                                           long          now,
                                           int           change_type );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ping_tracker_align( void );

FD_FN_CONST ulong
fd_ping_tracker_footprint( ulong entrypoints_len );

void *
fd_ping_tracker_new( void *                    shmem,
                     fd_rng_t *                rng,
                     ulong                     entrypoints_len,
                     fd_ip4_port_t const *     entrypoints,
                     fd_ping_tracker_change_fn change_fn,
                     void *                    change_fn_ctx );

fd_ping_tracker_t *
fd_ping_tracker_join( void * shpt );

/* fd_ping_tracker_track marks a peer for ping tracking.  This should be
   called every time a peer sends us a valid gossip contact info message
   so that we can start pinging them.

   The tracker is idempotent, and will only refresh and update
   information about the peer, based on knowledge that it sent us a new
   message and is still alive.  It is valid to register a peer pubkey
   with a new stake amount, or peer address, and the tracker will
   internally update the information. */

void
fd_ping_tracker_track( fd_ping_tracker_t * ping_tracker,
                       uchar const *       peer_pubkey,
                       ulong               peer_stake,
                       fd_ip4_port_t       peer_address,
                       long                now );

/* fd_ping_tracker_register registers a response pong from a peer so
   that they can be considered as valid.  It should be called any time
   a peer sends a valid-looking pong.  Valid looking, because it might
   not be ponging an actual ping token we sent, but this function will
   validate that before marking the peer as active. */

void
fd_ping_tracker_register( fd_ping_tracker_t * ping_tracker,
                          uchar const *       peer_pubkey,
                          ulong               peer_stake,
                          fd_ip4_port_t       peer_address,
                          uchar const *       pong_token,
                          long                now );

/* fd_ping_tracker_pop_request informs the caller if a ping request
   needs to be sent to a peer.  If a ping request needs to be sent, the
   peer pubkey is returned in out_peer_pubkey.  The caller should send a
   ping message to the peer.  The structure assumes the ping will be
   sent, and updates internal state accordingly.

   Returns 1 if a ping request needs to be sent, or 0 if no ping request
   is needed.

   The out_peer_pubkey is only valid if the return value is 1, and
   should only be used immediately.  The out_peer_pubkey is invalidated
   by any other call to the ping tracker, and using it after that is
   undefined behavior. */

int
fd_ping_tracker_pop_request( fd_ping_tracker_t *    ping_tracker,
                             long                   now,
                             uchar const **         out_peer_pubkey,
                             fd_ip4_port_t const ** out_peer_address,
                             uchar const **         out_token );

fd_ping_tracker_metrics_t const *
fd_ping_tracker_metrics( fd_ping_tracker_t const * ping_tracker );

#endif /* HEADER_fd_src_flamenco_gossip_fd_ping_tracker_h */
