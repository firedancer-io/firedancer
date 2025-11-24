#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h

#include "fd_gossip_private.h"

/* fd_gossip_txbuild_t provides a set of APIs to incrementally build a
   push or pull response message from CRDS values.  The caller is
   responsible for checking there is space before appending a new value,
   and flushing the final message. */

struct __attribute__((packed)) fd_gossip_crds_val_hdr {
  uchar sig[ 64UL ];
  uint  tag; /* CRDS value tag */
};

typedef struct fd_gossip_crds_val_hdr fd_gossip_crds_val_hdr_t;

struct __attribute__((packed)) fd_gossip_crds_msg {
  uint  msg_type;
  uchar identity_pubkey[ 32UL ];
  ulong crds_len;
  uchar crds[ ];
};

typedef struct fd_gossip_crds_msg fd_gossip_crds_msg_t;

struct fd_gossip_txbuild {
  uchar tag;

  ulong bytes_len;
  uchar bytes[ 1232UL ];

  ulong crds_len;
  struct {
   ulong tag;
   ulong off;
   ulong sz;
  } crds[ FD_GOSSIP_MSG_MAX_CRDS ];
};

typedef struct fd_gossip_txbuild fd_gossip_txbuild_t;

FD_PROTOTYPES_BEGIN

/* fd_gossip_txbuild_init() initializes the builder with the identity
   pubkey and message type (FD_GOSSIP_MESSAGE_PULL_RESPONSE or
   FD_GOSSIP_MESSAGE_PUSH). */

void
fd_gossip_txbuild_init( fd_gossip_txbuild_t * txbuild,
                        uchar const *         identity_pubkey,
                        uchar                 tag );

/* fd_gossip_txbuild_can_fit() returns 1 if the outgoing message can fit
   an additional CRDS value of size crds_len, or 0 otherwise.  If the
   message cannot fit it is undefined behavior to append it. */

int
fd_gossip_txbuild_can_fit( fd_gossip_txbuild_t const * txbuild,
                           ulong                       crds_len );

/* Appends the CRDS value to the builder->msg buffer. Assumes that
   fd_gossip_crds_msg_builder_needs_flush was called and addressed
   appropriately.

   On return builder->msg is a valid Gossip push/pullresp message of
   size builder->msg with N+1 CRDS values appended where N is the
   number of existing CRDS values prior to insertion of crds_val. */
void
fd_gossip_txbuild_append( fd_gossip_txbuild_t * txbuild,
                          ulong                 crds_len,
                          uchar const *         crds );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h */
