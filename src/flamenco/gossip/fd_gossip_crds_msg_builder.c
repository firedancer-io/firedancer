#include "fd_gossip_crds_msg_builder.h"
#include "fd_gossip_private.h"

#define CRDS_BUF_OFFSET ( 44UL ) /* Offset to the start of the CRDS value in the message buffer */

struct __attribute__((packed)) crds_msg {
  uint  msg_type;
  uchar identity_pubkey[ 32UL ];
  ulong crds_len;
  uchar crds[ ];
};

typedef struct crds_msg crds_msg_t;

void
fd_gossip_crds_msg_builder_init( fd_gossip_crds_msg_builder_t * builder,
                                 uchar const *                  identity_pubkey,
                                 uchar                          msg_type ) {
  fd_gossip_crds_msg_builder_reset( builder );
  crds_msg_t * msg = (crds_msg_t *)builder->msg;
  msg->msg_type = msg_type;
  fd_gossip_crds_msg_builder_set_identity_pubkey( builder, identity_pubkey );
}

void
fd_gossip_crds_msg_builder_reset( fd_gossip_crds_msg_builder_t * builder ) {
  builder->msg_sz = CRDS_BUF_OFFSET;
  crds_msg_t * msg = (crds_msg_t *)builder->msg;
  msg->crds_len = 0UL;
  fd_memset( builder->crds_meta, 0, sizeof(builder->crds_meta) );
}

void
fd_gossip_crds_msg_builder_set_identity_pubkey( fd_gossip_crds_msg_builder_t * builder,
                                                uchar const *                  identity_pubkey ) {
  crds_msg_t * msg = (crds_msg_t *)builder->msg;
  fd_memcpy( msg->identity_pubkey, identity_pubkey, 32UL );
}

ulong
fd_gossip_crds_msg_builder_get_crds_len( fd_gossip_crds_msg_builder_t const * builder ){
  crds_msg_t const * msg = (crds_msg_t const *)builder->msg;
  return msg->crds_len;
}

uint
fd_gossip_crds_msg_builder_get_msg_type( fd_gossip_crds_msg_builder_t const * builder ) {
  crds_msg_t const * msg = (crds_msg_t const *)builder->msg;
  return msg->msg_type;
}

int
fd_gossip_crds_msg_builder_needs_flush( fd_gossip_crds_msg_builder_t const * builder,
                                        ulong                                crds_sz ) {
  ulong remaining_space = fd_ulong_sat_sub( sizeof(builder->msg), builder->msg_sz );
  return remaining_space<crds_sz;
}

struct __attribute__((packed)) crds_val_hdr {
  uchar sig[ 64UL ];
  uint  tag; /* CRDS value tag */
};

typedef struct crds_val_hdr crds_val_hdr_t;

void
fd_gossip_crds_msg_builder_append( fd_gossip_crds_msg_builder_t * builder,
                                   uchar const *                  crds_val,
                                   ulong                          crds_sz ) {
  if( FD_UNLIKELY( crds_sz>FD_GOSSIP_CRDS_MAX_SZ ) ) {
    FD_LOG_WARNING(( "CRDS value size %lu exceeds expected maximum %lu", crds_sz, FD_GOSSIP_CRDS_MAX_SZ ));
  }
  fd_memcpy( &builder->msg[ builder->msg_sz ], crds_val, crds_sz );
  crds_msg_t *     msg = (crds_msg_t *)builder->msg;
  crds_val_hdr_t * hdr = (crds_val_hdr_t *)crds_val;

  fd_gossip_crds_builder_crds_meta_t * meta = &builder->crds_meta[ msg->crds_len ];
  meta->tag = hdr->tag;
  meta->off = (ushort)builder->msg_sz;
  meta->sz  = (ushort)crds_sz;

  msg->crds_len++;
  builder->msg_sz += crds_sz;

}
