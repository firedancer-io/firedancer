#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_private_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_private_h

#include "fd_active_set.h"
#include "fd_gossip.h"
#include "fd_crds.h"
#include "fd_gossip_msg.h"
#include "fd_ping_tracker.h"

typedef void (*fd_gossip_send_fn)( void *                 ctx,
                                   uchar const *          data,
                                   ulong                  sz,
                                   fd_ip4_port_t const *  peer_address );
typedef void (*fd_gossip_sign_fn)( void *         ctx,
                                   uchar const *  data,
                                   ulong          sz,
                                   uchar *        signature );
struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  fd_active_set_t *   active_set;
  fd_ping_tracker_t * ping_tracker;

  fd_gossip_message_t outgoing[ 1 ]; /* Not sure how to use this exactly */

  /* Callbacks */
  fd_gossip_sign_fn sign_fn;
  void *            sign_ctx;

  fd_gossip_send_fn send_fn;
  void *            send_ctx;
};

#endif
