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
   twenty seconds is eligible to be pinged, except nodes with at least
   one SOL of stake which are exempt from ping requirements.  Gossip
   entrypoints are also exempt.

   Once a peer has been pinged, we wait up to a second for a response
   before trying again.  We repeatedly retry pinging the peer until the
   peer responds, or their most recent message becomes older than twenty
   seconds.

   Once a peer is validated by responding to a ping with a valid pong,
   it is considered valid for 20 minutes.  After 18 minutes, we will
   begin pinging the peer again, every second, to refresh the peer. */

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
  ulong permanent_cnt;

  ulong ping_cnt;
  ulong tracked_cnt;
  ulong stake_changed_cnt;
  ulong address_changed_cnt;
  ulong evicted_cnt;
  ulong expired_cnt;
  ulong retired_cnt;

  ulong pong_result[ 5UL ];
};

typedef struct fd_ping_tracker_metrics fd_ping_tracker_metrics_t;

/* Change callbacks are delivered whenever a peer's status changes.  A
   peer can become active, become inactive, or be removed from the table
   completely.

   The callback includes the index of the peer in an imaginary array of
   peers.  A given peer (identified by public key) will always have the
   same index, including on its remove message.  Consumers of the change
   callbacks can therefore maintain a simple array of peers. */

#define FD_PING_TRACKER_CHANGE_TYPE_ACTIVE   (0)
#define FD_PING_TRACKER_CHANGE_TYPE_INACTIVE (1)
#define FD_PING_TRACKER_CHANGE_TYPE_REMOVE   (2)

typedef void (*fd_ping_tracker_change_fn)( void *        ctx,
                                           uchar const * peer_pubkey,
                                           fd_ip4_port_t peer_address,
                                           long          now,
                                           int           change_type,
                                           ulong         peer_idx );

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

fd_ping_tracker_metrics_t const *
fd_ping_tracker_metrics( fd_ping_tracker_t const * ping_tracker );

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

/* fd_ping_tracker_update_stake updates the stake amount associated with
   the given peer.  It is not an error to call this for an untracked
   peer.  This may cause peers to move in and out of exempted status. */

void
fd_ping_tracker_update_stake( fd_ping_tracker_t * ping_tracker,
                              uchar const *       peer_pubkey,
                              ulong               peer_stake,
                              long                now );

/* fd_ping_tracker_register registers a response pong from a peer so
   that they can be considered as valid.  It should be called any time
   a peer sends a valid-looking pong.  Valid looking, because it might
   not be ponging an actual ping token we sent, but this function will
   validate that before marking the peer as active. */

void
fd_ping_tracker_register( fd_ping_tracker_t * ping_tracker,
                          uchar const *       peer_pubkey,
                          fd_ip4_port_t       peer_address,
                          uchar const *       pong_token,
                          long                now );

/* fd_ping_tracker_advance advances the ping tracker to the provided
   time, checking various timeouts and performing actions as necessary.

   This function is idempotent and should be called as often as possible
   and before calling fd_ping_tracker_pop_request. */

void
fd_ping_tracker_advance( fd_ping_tracker_t * ping_tracker,
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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_ping_tracker_h */
