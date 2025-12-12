#include "fd_gossip_txbuild.h"

#include "fd_gossip_private.h"

struct __attribute__((packed)) crds_val_hdr {
  uchar sig[ 64UL ];
  uint  tag; /* CRDS value tag */
};

typedef struct crds_val_hdr crds_val_hdr_t;

struct __attribute__((packed)) crds_msg {
  uint msg_type;
  uchar identity_pubkey[ 32UL ];
  ulong crds_len;
  uchar crds[ ];
};

typedef struct crds_msg crds_msg_t;

void
fd_gossip_txbuild_init( fd_gossip_txbuild_t * txbuild,
                        uchar const *         identity_pubkey,
                        uchar                 msg_type ) {
  txbuild->tag = msg_type;
  txbuild->bytes_len = 44UL; /* offsetof( crds_msg_t, crds ) */
  txbuild->crds_cnt = 0UL;

  crds_msg_t * msg = (crds_msg_t *)txbuild->bytes;
  msg->msg_type = msg_type;
  fd_memcpy( msg->identity_pubkey, identity_pubkey, 32UL );
  msg->crds_len = 0UL;
}

int
fd_gossip_txbuild_can_fit( fd_gossip_txbuild_t const * txbuild,
                           ulong                       crds_len ) {
  return crds_len<=(sizeof(txbuild->bytes)-txbuild->bytes_len);
}

void
fd_gossip_txbuild_append( fd_gossip_txbuild_t * txbuild,
                          ulong                 crds_len,
                          uchar const *         crds ) {
  FD_TEST( crds_len<=FD_GOSSIP_CRDS_MAX_SZ );
  FD_TEST( fd_gossip_txbuild_can_fit( txbuild, crds_len ) );
  FD_TEST( txbuild->crds_cnt<sizeof(txbuild->crds)/sizeof(txbuild->crds[0]) );

  fd_memcpy( &txbuild->bytes[ txbuild->bytes_len ], crds, crds_len );

  crds_msg_t * msg = (crds_msg_t *)txbuild->bytes;
  msg->crds_len++;

  crds_val_hdr_t * hdr = (crds_val_hdr_t *)crds;

  txbuild->crds[ txbuild->crds_cnt ].tag = hdr->tag;
  txbuild->crds[ txbuild->crds_cnt ].off = (ushort)txbuild->bytes_len;
  txbuild->crds[ txbuild->crds_cnt ].sz  = (ushort)crds_len;
  txbuild->crds_cnt++;

  txbuild->bytes_len += crds_len;
}
