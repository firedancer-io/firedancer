/* fuzz_quic_wire is a simple and stateless fuzz target for fd_quic.

   The attack surface consists of fd_quic's packet handlers.
   The input vectors are the raw contents of UDP datagrams (in encrypted
   form)  A custom mutator is used to temporarily remove the decryption
   before calling the generic libFuzzer mutator.  If we tried mutating
   the encrypted inputs directly, everything would just be an encryption
   failure.

   The goal of fuzz_quic_wire is to cover the early upstream stages of
   the QUIC packet processing pipeline.  This includes packet header
   parsing, connection creation, retry handling, etc. */

#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_quic_test_helpers.h"
#include "../crypto/fd_quic_crypto_suites.h"
#include "../templ/fd_quic_parse_util.h"
#include "../../tls/test_tls_helper.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#include "../fd_quic_proto.h"
#include "../fd_quic_private.h"

#include <assert.h>

static fd_quic_crypto_suite_t const * suite;
static fd_quic_crypto_keys_t const    keys[1] = {{
  .pkt_key    = {0},
  .pkt_key_sz = 32UL,
  .iv         = {0},
  .iv_sz      = 12UL,
  .hp_key     = {0},
  .hp_key_sz  = 32UL
}};

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
  fd_log_level_logfile_set(0);
  fd_log_level_stderr_set(0);

  static fd_quic_crypto_ctx_t crypto_ctx[1];
  fd_quic_crypto_ctx_init( crypto_ctx );
  suite = &crypto_ctx->suites[ TLS_AES_128_GCM_SHA256_ID ];
  return 0;
}

static int
_aio_send( void *                    ctx,
           fd_aio_pkt_info_t const * batch,
           ulong                     batch_cnt,
           ulong *                   opt_batch_idx,
           int                       flush ) {
  (void)flush;
  (void)batch;
  (void)batch_cnt;
  (void)opt_batch_idx;
  (void)ctx;
  return 0;
}

static void
send_udp_packet( fd_quic_t *   quic,
                 uchar const * data,
                 ulong         size ) {

  uchar buf[16384];

  ulong headers_sz = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

  uchar * cur = buf;
  uchar * end = buf + sizeof(buf);

  fd_eth_hdr_t eth = { .net_type = FD_ETH_HDR_TYPE_IP };
  fd_ip4_hdr_t ip4 = {
    .verihl   = FD_IP4_VERIHL(4,5),
    .protocol = FD_IP4_HDR_PROTOCOL_UDP,
  };
  fd_udp_hdr_t udp = {0};

  /* Guaranteed to not overflow */
  fd_quic_encode_eth( cur, (ulong)( end-cur ), &eth ); cur += sizeof(fd_eth_hdr_t);
  fd_quic_encode_ip4( cur, (ulong)( end-cur ), &ip4 ); cur += sizeof(fd_ip4_hdr_t);
  fd_quic_encode_udp( cur, (ulong)( end-cur ), &udp ); cur += sizeof(fd_udp_hdr_t);

  if( cur + size > end ) return;
  fd_memcpy( cur, data, size );

  /* Main fuzz entrypoint */

  fd_quic_process_packet( quic, buf, headers_sz + size );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Memory region to hold the QUIC instance */
  static uchar quic_mem[ 1<<23 ] __attribute__((aligned(FD_QUIC_ALIGN)));

  /* Create ultra low limits for QUIC instance for maximum performance */
  fd_quic_limits_t const quic_limits = {
    .conn_cnt         = 2,
    .handshake_cnt    = 16,
    .conn_id_cnt      = 16,
    .conn_id_sparsity = 1.0,
    .stream_cnt       = { 1, 1, 1, 1 },
    .stream_sparsity  = 1.0,
    .inflight_pkt_cnt = 8UL,
    .tx_buf_sz        = 4096UL,
    .stream_pool_cnt  = 16
  };

  /* Enable features depending on the last few bits.  The last bits are
     pseudorandom (either ignored or belong to the MAC tag) */
  uint last_byte = 0U;
  if( size > 0 ) last_byte = data[ size-1 ];
  int enable_retry = !!(last_byte & 1);
  int role         =   (last_byte & 2) ? FD_QUIC_ROLE_SERVER : FD_QUIC_ROLE_CLIENT;
  int established  = !!(last_byte & 4);

  assert( fd_quic_footprint( &quic_limits ) <= sizeof(quic_mem) );
  void *      shquic = fd_quic_new( quic_mem, &quic_limits );
  fd_quic_t * quic   = fd_quic_join( shquic );

  fd_quic_config_anonymous( quic, role );

  fd_tls_test_sign_ctx_t test_signer = fd_tls_test_sign_ctx( rng );
  fd_quic_config_test_signer( quic, &test_signer );

  quic->config.retry = enable_retry;

  fd_aio_t aio_[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( aio_, NULL, _aio_send ) );
  assert( aio );

  fd_quic_set_aio_net_tx( quic, aio );
  assert( fd_quic_init( quic ) );

  /* Create dummy connection */
  fd_quic_conn_id_t our_conn_id  = { .sz=8 };
  fd_quic_conn_id_t peer_conn_id = { .sz=8 };
  uint              dst_ip_addr  = 0U;
  ushort            dst_udp_port = (ushort)0;

  fd_quic_conn_t * conn =
    fd_quic_conn_create( quic,
                        &our_conn_id, &peer_conn_id,
                        dst_ip_addr,  (ushort)dst_udp_port,
                        1,  /* we are the server */
                        1   /* QUIC version 1 */ );
  assert( conn );

  conn->tx_max_data                            =       512UL;
  conn->tx_initial_max_stream_data_uni         =        64UL;
  conn->tx_initial_max_stream_data_bidi_local  =        64UL;
  conn->tx_initial_max_stream_data_bidi_remote =        64UL;
  conn->rx_max_data                            =       512UL;
  conn->rx_initial_max_stream_data_uni         =        64UL;
  conn->rx_initial_max_stream_data_bidi_local  =        64UL;
  conn->rx_initial_max_stream_data_bidi_remote =        64UL;
  conn->tx_max_datagram_sz                     = FD_QUIC_MTU;
  fd_quic_conn_set_max_streams( conn, 0, 1 );
  fd_quic_conn_set_max_streams( conn, 1, 1 );
  conn->peer_sup_stream_id[ 0 ] = 32UL;
  conn->peer_sup_stream_id[ 1 ] = 32UL;
  conn->peer_sup_stream_id[ 2 ] = 32UL;
  conn->peer_sup_stream_id[ 3 ] = 32UL;

  if( established ) {
    conn->state = FD_QUIC_CONN_STATE_ACTIVE;
    conn->suites[ fd_quic_enc_level_initial_id    ] = suite;
    conn->suites[ fd_quic_enc_level_early_data_id ] = suite;
    conn->suites[ fd_quic_enc_level_handshake_id  ] = suite;
    conn->suites[ fd_quic_enc_level_appdata_id    ] = suite;
  }

  /* Calls fuzz entrypoint */
  send_udp_packet( quic, data, size );
  fd_quic_service( quic );

  fd_quic_delete( fd_quic_leave( fd_quic_fini( quic ) ) );
  fd_aio_delete( fd_aio_leave( aio ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

/* guess_packet_size attempts to discover the end of a QUIC packet.
   Returns the total length (including GCM tag) on success, sets *pn_off
   to the packet number offset and *pn to the packet number.  Returns
   0UL on failure. */

static ulong
guess_packet_size( uchar const * data,
                   ulong         size,
                   ulong *       pn_off ) {

  uchar const * cur_ptr = data;
  ulong         cur_sz  = size;

  ulong pkt_num_pnoff = 0UL;
  ulong total_len     = size;

  fd_quic_common_hdr_t common_hdr[1];
  ulong rc = fd_quic_decode_common_hdr( common_hdr, data, size );
  if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
  cur_ptr += rc; cur_sz -= rc;

  if( common_hdr->hdr_form == 1 ) {  /* long header */

    fd_quic_long_hdr_t long_hdr[1];
    rc = fd_quic_decode_long_hdr( long_hdr, cur_ptr, cur_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
    cur_ptr += rc; cur_sz -= rc;

    switch( common_hdr->long_packet_type ) {
    case FD_QUIC_PKTTYPE_V1_INITIAL: {
      fd_quic_initial_t initial[1];
      rc = fd_quic_decode_initial( initial, cur_ptr, cur_sz );
      if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
      cur_ptr += rc; cur_sz -= rc;

      pkt_num_pnoff = initial->pkt_num_pnoff;
      total_len     = pkt_num_pnoff + initial->len;
      break;
    }
    case FD_QUIC_PKTTYPE_V1_HANDSHAKE: {
      fd_quic_handshake_t handshake[1];
      rc = fd_quic_decode_handshake( handshake, cur_ptr, cur_sz );
      if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
      cur_ptr += rc; cur_sz -= rc;

      pkt_num_pnoff = handshake->pkt_num_pnoff;
      total_len     = pkt_num_pnoff + handshake->len;
      break;
    }
    case FD_QUIC_PKTTYPE_V1_RETRY:
      /* Do we need to decrypt Retry packets?  I'm not sure */
      /* TODO correctly derive size of packet in case there is another
              packet following the retry packet */
      return 0UL;
    case FD_QUIC_PKTTYPE_V1_ZERO_RTT:
      /* No support for 0-RTT yet */
      return 0UL;
    default:
      __builtin_unreachable();
    }

  } else {  /* short header */

    fd_quic_one_rtt_t one_rtt[1];
    rc = fd_quic_decode_one_rtt( one_rtt, cur_ptr, cur_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
    cur_ptr += rc; cur_sz -= rc;

    pkt_num_pnoff = one_rtt->pkt_num_pnoff;

  }

  *pn_off = pkt_num_pnoff;
  return total_len;
}

/* decrypt_packet attempts to decrypt the first QUIC packet in the given
   buffer.  data points to the first byte of the QUIC packet.  size is
   the number of bytes until the end of the UDP datagram.  Returns the
   number of bytes that belonged to the first packet (<= size) on
   success.  Returns 0 on failure and leaves the packet (partially)
   encrypted. */

static ulong
decrypt_packet( uchar * const data,
                ulong   const size ) {

  ulong pkt_num_pnoff = 0UL;
  ulong total_len = guess_packet_size( data, size, &pkt_num_pnoff );
  if( !total_len ) return 0UL;

  /* Decrypt the packet */

  int decrypt_res = fd_quic_crypto_decrypt_hdr( data, size, pkt_num_pnoff, suite, keys );
  if( decrypt_res != FD_QUIC_SUCCESS ) return 0UL;

  uint  pkt_number_sz = ( (uint)data[0] & 0x03U ) + 1U;
  ulong pkt_number =
    fd_quic_parse_bits( data + pkt_num_pnoff,
                        0, 8U * pkt_number_sz );

  decrypt_res =
    fd_quic_crypto_decrypt( data,           size,
                            pkt_num_pnoff,  pkt_number,
                            suite,          keys );
  if( decrypt_res != FD_QUIC_SUCCESS ) return 0UL;

  return fd_ulong_min( total_len + FD_QUIC_CRYPTO_TAG_SZ, size );
}

/* decrypt_payload attempts to remove packet protection of a UDP
   datagram payload in-place.  Note that a UDP datagram can contain
   multiple QUIC packets. */

static int
decrypt_payload( uchar * data,
                 ulong   size ) {

  if( size < 16 ) return 0;

  /* Heuristic: If the last 16 bytes of the packet (the AES-GCM tag) are
     zero consider it an unencrypted packet */

  uint mask=0U;
  for( ulong j=0UL; j<16UL; j++ ) mask |= data[size-16+j];
  if( !mask ) return 1;

  uchar * cur_ptr = data;
  ulong   cur_sz  = size;

  do {

    ulong sz = decrypt_packet( cur_ptr, cur_sz );
    if( !sz ) return 0;
    assert( sz <= cur_sz );  /* prevent out of bounds */

    cur_ptr += sz;  cur_sz -= sz;

  } while( cur_sz );

  return 1;
}

static ulong
encrypt_packet( uchar * const data,
                ulong   const size ) {

  uchar out[ FD_QUIC_MTU ];

  ulong pkt_num_pnoff = 0UL;
  ulong total_len = guess_packet_size( data, size, &pkt_num_pnoff );
  if( ( total_len < FD_QUIC_CRYPTO_TAG_SZ ) |
      ( total_len > size                  ) |
      ( total_len > sizeof(out)           ) )
    return size;

  uchar first = data[0];
  ulong pkt_number_sz = ( first & 0x03u ) + 1;

  ulong         out_sz = total_len;
  uchar const * hdr    = data;
  ulong         hdr_sz = pkt_num_pnoff + pkt_number_sz;

  if( ( out_sz          < hdr_sz ) |
      ( out_sz - hdr_sz < FD_QUIC_CRYPTO_TAG_SZ ) )
    return size;

  uchar const * pay    = hdr + hdr_sz;
  ulong         pay_sz = out_sz - hdr_sz - FD_QUIC_CRYPTO_TAG_SZ;

  int encrypt_res =
    fd_quic_crypto_encrypt( out, &out_sz,
                            hdr, hdr_sz,
                            pay, pay_sz,
                            suite, keys, keys );
  if( encrypt_res != FD_QUIC_SUCCESS )
    return size;
  assert( out_sz == total_len );

  fd_memcpy( data, out, out_sz );
  return out_sz;
}

static void
encrypt_payload( uchar * data,
                 ulong   size ) {

  uchar * cur_ptr = data;
  ulong   cur_sz  = size;

  while( cur_sz ) {
    ulong sz = encrypt_packet( cur_ptr, cur_sz );
    assert( sz );            /* prevent infinite loop */
    assert( sz <= cur_sz );  /* prevent out of bounds */

    cur_ptr += sz;  cur_sz -= sz;
  }
}

/* LLVMFuzzerCustomMutator has the following behavior:

   - If the input is not encrypted, mutates the raw input, and produces
     an encrypted output
   - If the input is encrypted, mutates the decrypted input, and
     produces another encrypted output
   - If the input appears to be encrypted but fails to decrypt, mutates
     the raw encrypted input, and produces another output that will fail
     to decrypt. */

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   data_sz,
                         ulong   max_sz,
                         uint    seed ) {
  int ok = decrypt_payload( data, data_sz );
  data_sz = LLVMFuzzerMutate( data, data_sz, max_sz );
  if( ok ) encrypt_payload( data, data_sz );
  (void)seed;
  return data_sz;
}

/* Find a strategy for custom crossover of decrypted packets */
