#include "fd_pcap.h"

ulong
test_clock( void * ctx );

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin );

FD_FN_UNUSED static void
init_quic( fd_quic_t *  quic,
           char const * hostname,
           uint         ip_addr,
           uint         udp_port ) {

  FD_LOG_NOTICE(( "Configuring QUIC \"%s\"", hostname ));

  fd_quic_config_t * quic_config = fd_quic_get_config( quic );

  strcpy ( quic_config->cert_file, "cert.pem" );
  strcpy ( quic_config->key_file,  "key.pem"  );
  strncpy( quic_config->sni,       hostname, FD_QUIC_SNI_LEN );

  quic_config->link.src_mac_addr[ 0 ] = 0x01;
  quic_config->link.dst_mac_addr[ 0 ] = 0x01;

  quic_config->net.ip_addr         = ip_addr;
  quic_config->net.listen_udp_port = (ushort)udp_port;

  quic_config->net.ephem_udp_port.lo = 4219;
  quic_config->net.ephem_udp_port.hi = 4220;

  quic_config->idle_timeout = 5e6;

  fd_quic_callbacks_t * quic_cb = fd_quic_get_callbacks( quic );

  quic_cb->stream_receive = my_stream_receive_cb;

  quic_cb->now     = test_clock;
  quic_cb->now_ctx = NULL;
}

FD_FN_UNUSED static void
write_shb( FILE * file ) {
  pcap_shb_t shb[1] = {{ 0x0A0D0D0A, sizeof( pcap_shb_t ), 0x1A2B3C4D, 1, 0, (ulong)-1, sizeof( pcap_shb_t ) }};
  FD_TEST( fwrite( shb, sizeof(shb), 1, file )==1 );
}

FD_FN_UNUSED static void
write_idb( FILE * file ) {
  pcap_idb_t idb[1] = {{ 0x00000001, sizeof( pcap_idb_t ), 1, 0, 0, sizeof( pcap_idb_t ) }};
  FD_TEST( fwrite( idb, sizeof(idb), 1, file )==1 );
}

void
write_epb( FILE *  file,
           uchar * buf,
           uint    buf_sz,
           ulong   ts ) {

  if( buf_sz == 0 ) return;

  uint ts_lo = (uint)ts;
  uint ts_hi = (uint)( ts >> 32u );

  uint align_sz = ( ( buf_sz - 1u ) | 0x03u ) + 1u;
  uint tot_len  = align_sz + (uint)sizeof( pcap_epb_t ) + 4;
  pcap_epb_t epb[1] = {{
    0x00000006,
    tot_len,
    0, /* intf id */
    ts_hi,
    ts_lo,
    buf_sz,
    buf_sz }};

  FD_TEST( fwrite( epb, sizeof( epb ), 1, file )==1 );
  FD_TEST( fwrite( buf, buf_sz,        1, file )==1 );

  if( align_sz > buf_sz ) {
    /* write padding */
    uchar pad[4] = {0};
    FD_TEST( fwrite( pad, align_sz - buf_sz, 1, file )==1 );
  }

  FD_TEST( fwrite( &tot_len, 4, 1, file )==1 );
}
