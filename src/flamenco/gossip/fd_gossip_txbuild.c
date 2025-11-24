#include "fd_gossip_txbuild.h"

#include "fd_gossip_private.h"

void
fd_gossip_txbuild_init( fd_gossip_txbuild_t * txbuild,
                        uchar const *         identity_pubkey,
                        uchar                 msg_type ) {
  txbuild->tag = msg_type;
  txbuild->bytes_len = 44UL; /* offsetof( fd_gossip_crds_msg_t, crds ) */
  txbuild->crds_len = 0UL;

  fd_gossip_crds_msg_t * msg = (fd_gossip_crds_msg_t *)txbuild->bytes;
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
  FD_TEST( txbuild->crds_len<sizeof(txbuild->crds)/sizeof(txbuild->crds[0]) );

  fd_memcpy( &txbuild->bytes[ txbuild->bytes_len ], crds, crds_len );

  fd_gossip_crds_msg_t * msg = (fd_gossip_crds_msg_t *)txbuild->bytes;
  msg->crds_len++;

  fd_gossip_crds_val_hdr_t * hdr = (fd_gossip_crds_val_hdr_t *)crds;
  ulong crds_tag = (ulong)hdr->tag;
  if( FD_UNLIKELY( crds_tag>FD_GOSSIP_VALUE_LAST ) ) {
    FD_LOG_ERR(( "fd_gossip_txbuild_append: tag %lu out of range (txbuild=%p msg_tag=%u crds_len=%lu sz=%lu)",
                     crds_tag, (void *)txbuild, (uint)txbuild->tag, txbuild->crds_len, crds_len ));
  }

  txbuild->crds[ txbuild->crds_len ].tag = crds_tag;
  txbuild->crds[ txbuild->crds_len ].off = (ushort)txbuild->bytes_len;
  txbuild->crds[ txbuild->crds_len ].sz  = (ushort)crds_len;
  txbuild->crds_len++;

  txbuild->bytes_len += crds_len;
}
