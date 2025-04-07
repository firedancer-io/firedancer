#include "fd_snp_app.h"

ulong
fd_snp_app_footprint( fd_snp_app_limits_t * limits ) {
  (void)limits;
  return sizeof( fd_snp_app_t );
}

void *
fd_snp_app_new( void * mem ) {
  return mem;
}

fd_snp_app_t *
fd_snp_app_join( void * shsnp ) {
  return (fd_snp_app_t *)(shsnp);
}

fd_snp_app_meta_t
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
                 ulong                packet_sz ) { /* size of input packet */
  // FIXME
  uchar const * data = packet;
  ulong data_sz = packet_sz;
  fd_snp_app_peer_t peer = 0;
  fd_snp_app_meta_t meta = 0;

  return ctx->cb.rx( peer, data, data_sz, meta );
}

int
fd_snp_app_send( fd_snp_app_t const * ctx,          /* snp_app context */
                 uchar *              packet,       /* output packet buffer */
                 ulong                packet_sz,    /* (max) size of output packet buffer */
                 fd_snp_app_peer_t    peer,         /* destination peer */
                 void const *         data,         /* app data to send to peer */
                 ulong                data_sz,      /* size of app data to send to peer */
                 fd_snp_app_meta_t    meta ) {      /* connection metadata */
  (void)peer;
  (void)data;
  (void)data_sz;
  ulong actual_packet_sz = packet_sz; // FIXME

  return ctx->cb.tx( packet, actual_packet_sz, meta );
}

int
fd_snp_app_send_many( FD_PARAM_UNUSED fd_snp_app_t const * ctx,
                      FD_PARAM_UNUSED uchar *              packet,
                      FD_PARAM_UNUSED ulong                packet_sz,
                      FD_PARAM_UNUSED fd_snp_app_peer_t *  peers,
                      FD_PARAM_UNUSED ulong                peers_sz,
                      FD_PARAM_UNUSED void const *         data,
                      FD_PARAM_UNUSED ulong                data_sz,
                      FD_PARAM_UNUSED fd_snp_app_meta_t    meta ) {
  return FD_SNP_APP_FAILURE;
}

int
fd_snp_app_send_broadcast( FD_PARAM_UNUSED fd_snp_app_t const * ctx,
                           FD_PARAM_UNUSED uchar *              packet,
                           FD_PARAM_UNUSED ulong                packet_sz,
                           FD_PARAM_UNUSED void const *         data,
                           FD_PARAM_UNUSED ulong                data_sz,
                           FD_PARAM_UNUSED fd_snp_app_meta_t    meta ) {
  return FD_SNP_APP_FAILURE;
}
