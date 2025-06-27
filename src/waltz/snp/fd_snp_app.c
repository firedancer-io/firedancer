#include "fd_snp_app.h"
#include "../../util/net/fd_net_headers.h"

ulong
fd_snp_app_footprint( fd_snp_app_limits_t const * limits ) {
  (void)limits;
  return sizeof( fd_snp_app_t );
}

void *
fd_snp_app_new( void * mem, fd_snp_app_limits_t const * limits ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !limits ) ) return NULL;

  ulong align = fd_snp_app_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) return NULL;

  /* Zero the entire memory region */
  fd_snp_app_t * snp = (fd_snp_app_t *)mem;
  memset( snp, 0, fd_snp_app_footprint( limits ) );

  /* Store the limits */
  snp->limits = *limits;

  /* Set magic number to indicate successful initialization */
  FD_COMPILER_MFENCE();
  snp->magic = FD_SNP_APP_MAGIC;
  FD_COMPILER_MFENCE();

  return snp;
}

fd_snp_app_t *
fd_snp_app_join( void * shsnp ) {
  return (fd_snp_app_t *)(shsnp);
}

int
fd_snp_app_recv( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar const *        packet,       /* input packet */
                 ulong                packet_sz,    /* size of input packet */
                 fd_snp_meta_t        meta ) {      /* connection metadata */
  uchar const * data = NULL;
  ulong data_sz = 0UL;

  ulong proto = meta & FD_SNP_META_PROTO_MASK;
  switch( proto ) {
    case FD_SNP_META_PROTO_UDP:
      data    = packet    + sizeof(fd_ip4_udp_hdrs_t);
      data_sz = packet_sz - sizeof(fd_ip4_udp_hdrs_t);
      break;
    case FD_SNP_META_PROTO_V1:
      data = packet + sizeof(fd_ip4_udp_hdrs_t) + 15;            /* 12 is for SNP header + 3 for TL */
      data_sz = packet_sz - sizeof(fd_ip4_udp_hdrs_t) - 15 - 19; /* 19 is for final TL-MAC */
      if( FD_UNLIKELY( fd_snp_ip_is_multicast( packet ) ) ) {
        data_sz += 19;
        meta |= FD_SNP_META_OPT_BROADCAST;
      }
      break;
    default:
      return FD_SNP_FAILURE; /* Not implemented */
  }

  fd_snp_peer_t peer = 0;

  return ctx->cb.rx ? ctx->cb.rx( ctx->cb.ctx, peer, data, data_sz, meta ) : (int)data_sz;
}

int
fd_snp_app_send( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar *              packet,       /* output packet buffer */
                 ulong                packet_sz,    /* (max) size of output packet buffer */
                 void const *         data,         /* app data to send to peer */
                 ulong                data_sz,      /* size of app data to send to peer */
                 fd_snp_meta_t        meta ) {      /* connection metadata */
  ulong data_offset = 0UL;
  ulong actual_packet_sz = 0UL;

  ulong proto = meta & FD_SNP_META_PROTO_MASK;
  switch( proto ) {
    case FD_SNP_META_PROTO_UDP:
      data_offset = sizeof(fd_ip4_udp_hdrs_t);
      actual_packet_sz = data_sz + data_offset;
      break;
    case FD_SNP_META_PROTO_V1:
      data_offset = sizeof(fd_ip4_udp_hdrs_t) + 12;  /* 12 is for SNP header */

      if( FD_LIKELY( packet!=NULL ) ) {
        packet[data_offset] = FD_SNP_FRAME_DATAGRAM;
        ushort data_sz_h = (ushort)data_sz;
        memcpy( packet+data_offset+1, &data_sz_h, 2 );
      }
      data_offset += 3;

      actual_packet_sz = data_sz + data_offset + 19; /* 19 is for final MAC */
      break;
    default:
      return FD_SNP_FAILURE; /* Not implemented */
  }

  if( FD_UNLIKELY( packet_sz < actual_packet_sz ) ) {
    return FD_SNP_FAILURE;
  }
  if( FD_LIKELY( packet!=NULL ) ) memcpy( packet + data_offset, data, data_sz );

  return ctx->cb.tx ? ctx->cb.tx( ctx->cb.ctx, packet, actual_packet_sz, meta ) : (int)actual_packet_sz;
}

int
fd_snp_app_send_many( FD_PARAM_UNUSED fd_snp_app_t const * ctx,
                      FD_PARAM_UNUSED uchar *              packet,
                      FD_PARAM_UNUSED ulong                packet_sz,
                      FD_PARAM_UNUSED fd_snp_peer_t *      peers,
                      FD_PARAM_UNUSED ulong                peers_sz,
                      FD_PARAM_UNUSED void const *         data,
                      FD_PARAM_UNUSED ulong                data_sz,
                      FD_PARAM_UNUSED fd_snp_meta_t        meta ) {
  return FD_SNP_FAILURE; /* Not implemented */
}

int
fd_snp_app_send_broadcast( FD_PARAM_UNUSED fd_snp_app_t const * ctx,
                           FD_PARAM_UNUSED uchar *              packet,
                           FD_PARAM_UNUSED ulong                packet_sz,
                           FD_PARAM_UNUSED void const *         data,
                           FD_PARAM_UNUSED ulong                data_sz,
                           FD_PARAM_UNUSED fd_snp_meta_t        meta ) {
  return FD_SNP_FAILURE; /* Not implemented */
}
