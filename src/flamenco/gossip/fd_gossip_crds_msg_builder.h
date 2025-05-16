#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_msg_builder_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_msg_builder_h
#include "../../util/fd_util.h"
#include "fd_gossip_private.h"

/* fd_gossip_crds_msg_builder provides a set of APIs to iteratively
   build a Gossip Push or Pull Response payload with CRDS values. The
   user is in charge of flushing the builder state, and checking if a
   builder must be flushed before appending a new CRDS value. A flushed
   message should be reset/init prior to appending new values. */

struct fd_gossip_crds_builder_crds_meta {
   uint   tag;
   ushort off;
   ushort sz;
};
typedef struct fd_gossip_crds_builder_crds_meta fd_gossip_crds_builder_crds_meta_t;

struct fd_gossip_crds_msg_builder {
  uchar                              msg[ 1232UL ];
  ulong                              msg_sz; /* Also functions as cursor */
  fd_gossip_crds_builder_crds_meta_t crds_meta[ FD_GOSSIP_MSG_MAX_CRDS ];
};
typedef struct fd_gossip_crds_msg_builder fd_gossip_crds_msg_builder_t;



FD_PROTOTYPES_BEGIN

/* fd_gossip_crds_msg_builder_init initializes the builder with the
  identity pubkey and message type
  (FD_GOSSIP_MESSAGE_PULL_RESPONSE or FD_GOSSIP_MESSAGE_PUSH).

  On return, builder->msg is a valid Gossip push/pullresp message of
  size builder->msg_sz with 0 CRDS values appended.*/

void
fd_gossip_crds_msg_builder_init( fd_gossip_crds_msg_builder_t * builder,
                                 uchar const *                  identity_pubkey,
                                 uchar                          msg_type );

/* fd_gossip_crds_msg_builder_reset resets the state of the builder
   after builder->msg has been flushed by user. The identity pubkey and
   message type are preserved.

   On return, builder->msg is a valid Gossip push/pullresp message of
   size builder->msg_sz with 0 CRDS values appended. */
void
fd_gossip_crds_msg_builder_reset( fd_gossip_crds_msg_builder_t * builder );

void
fd_gossip_crds_msg_builder_set_identity_pubkey( fd_gossip_crds_msg_builder_t * builder,
                                                uchar const *                  identity_pubkey );

ulong
fd_gossip_crds_msg_builder_get_crds_len( fd_gossip_crds_msg_builder_t const * builder );

uint
fd_gossip_crds_msg_builder_get_msg_type( fd_gossip_crds_msg_builder_t const * builder );

/* fd_gossip_crds_msg_builder_needs_flush returns 1 if the message
   buffer must be flushed before it can fit in a new CRDS value of
   payload_sz . Returns 0 otherwise. */
int
fd_gossip_crds_msg_builder_needs_flush( fd_gossip_crds_msg_builder_t const * builder,
                                        ulong                                crds_sz );

/* Appends the CRDS value to the builder->msg buffer. Assumes that
   fd_gossip_crds_msg_builder_needs_flush was called and addressed
   appropriately.

   On return builder->msg is a valid Gossip push/pullresp message of
   size builder->msg with N+1 CRDS values appended where N is the
   number of existing CRDS values prior to insertion of crds_val. */
void
fd_gossip_crds_msg_builder_append( fd_gossip_crds_msg_builder_t * builder,
                                   uchar const *                  crds_val,
                                   ulong                          crds_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_msg_builder_h */
