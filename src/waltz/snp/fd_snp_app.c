#include "fd_snp_app.h"

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

  //TODO: check limits, and size based on limits

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

fd_snp_meta_t
fd_snp_app_into_meta( ulong  snp_proto,
                      uint   ip4,
                      ushort port ) {
  return ( snp_proto )
    | (( (ulong) port ) << 32 )
    | (( (ulong) ip4  )       );
}

int
fd_snp_app_recv( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar const *        packet,       /* input packet */
                 ulong                packet_sz,    /* size of input packet */
                 fd_snp_meta_t        meta ) {      /* connection metadata */
  // FIXME: extract meta and peer info from packet
  fd_snp_peer_t peer = 0;

  //TODO: UDP vs SNP
  uchar const * data = packet + sizeof(fd_ip4_udp_hdrs_t);
  ulong data_sz = packet_sz - sizeof(fd_ip4_udp_hdrs_t);

  return ctx->cb.rx( ctx->cb.ctx, peer, data, data_sz, meta );
}

int
fd_snp_app_send( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar *              packet,       /* output packet buffer */
                 ulong                packet_sz,    /* (max) size of output packet buffer */
                 void const *         data,         /* app data to send to peer */
                 ulong                data_sz,      /* size of app data to send to peer */
                 fd_snp_meta_t        meta ) {      /* connection metadata */
  //TODO: UDP vs SNP
  ulong data_offset = sizeof(fd_ip4_udp_hdrs_t) + 8; //TODO: 8 is for SNP session id
  ulong actual_packet_sz = data_sz + data_offset + 16; //TODO: 16 is for final MAC
  if( FD_UNLIKELY( packet_sz < actual_packet_sz ) ) {
    return FD_SNP_FAILURE;
  }

  memcpy( packet + data_offset, data, data_sz );
  return ctx->cb.tx( ctx->cb.ctx, packet, actual_packet_sz, meta );
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
  return FD_SNP_APP_FAILURE;
}

int
fd_snp_app_send_broadcast( FD_PARAM_UNUSED fd_snp_app_t const * ctx,
                           FD_PARAM_UNUSED uchar *              packet,
                           FD_PARAM_UNUSED ulong                packet_sz,
                           FD_PARAM_UNUSED void const *         data,
                           FD_PARAM_UNUSED ulong                data_sz,
                           FD_PARAM_UNUSED fd_snp_meta_t        meta ) {
  return FD_SNP_APP_FAILURE;
}
