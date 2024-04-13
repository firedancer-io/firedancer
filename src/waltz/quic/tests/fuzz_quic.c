#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../../util/sanitize/fd_fuzz.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "../fd_quic_proto.h"

#include "fd_quic_test_helpers.h"
#include "../../tls/test_tls_helper.h"
#include "../fd_quic_private.h"
#include "../../../ballet/x509/fd_x509_mock.h"

fd_quic_t *server_quic = NULL;

uchar scratch[0x4000];
size_t scratch_sz = 0x4000;

fd_aio_t _aio[1];

struct fd_quic_pkt_hdr {
  union {
    fd_quic_initial_t   initial;
    fd_quic_handshake_t handshake;
    fd_quic_one_rtt_t   one_rtt;
    fd_quic_retry_t     retry;
    /* don't currently support early data */
  } quic_pkt;
  uint enc_level; /* implies the type of quic_pkt */
};
typedef struct fd_quic_pkt_hdr fd_quic_pkt_hdr_t;
ulong fd_quic_pkt_hdr_encode(uchar *cur_ptr, ulong cur_sz, fd_quic_pkt_hdr_t *pkt_hdr, uint enc_level);
ulong fd_quic_pkt_hdr_footprint( fd_quic_pkt_hdr_t * pkt_hdr, uint enc_level );
void fd_quic_pkt_hdr_set_payload_sz( fd_quic_pkt_hdr_t * pkt_hdr, uint enc_level, uint payload_sz );
uint fd_quic_pkt_hdr_pkt_number_len( fd_quic_pkt_hdr_t * pkt_hdr,uint enc_level );

ulong test_clock(void *ctx) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

int test_aio_send_func(void *ctx, fd_aio_pkt_info_t const *batch,
                       ulong batch_cnt, ulong *opt_batch_idx, int flush) {
  (void)flush;
  (void)batch;
  (void)batch_cnt;
  (void)opt_batch_idx;
  (void)ctx;
  return 0;
}

uint send_packet(uchar const *payload, size_t payload_sz, uint pkt_type) {

  if (FD_UNLIKELY(payload_sz <= 0L)) {
    return 0u;
  }

  uchar *cur_ptr = scratch;
  ulong cur_sz = scratch_sz;

  fd_quic_pkt_t pkt;

  memcpy(pkt.eth->dst, "\x52\xF1\x7E\xDA\x2C\xE0", 6);
  memcpy(pkt.eth->src, "\x52\xF1\x7E\xDA\x2C\xE0", 6);
  pkt.eth->net_type = FD_ETH_HDR_TYPE_IP;

  pkt.ip4->verihl = FD_IP4_VERIHL(4,5);
  pkt.ip4->tos = 0;
  pkt.ip4->net_tot_len = (ushort)(20 + 8 + payload_sz);
  pkt.ip4->net_id = 0;
  pkt.ip4->net_frag_off = 0x4000u;
  pkt.ip4->ttl = 64; /* TODO make configurable */
  pkt.ip4->protocol = FD_IP4_HDR_PROTOCOL_UDP;
  pkt.ip4->check = 0;

  pkt.udp->net_sport = 0x2;
  pkt.udp->net_dport = 0x1;
  pkt.udp->net_len = (ushort)(8 + payload_sz);
  pkt.udp->check = 0x0000;

  ulong rc = fd_quic_encode_eth(cur_ptr, cur_sz, pkt.eth);

  if (FD_UNLIKELY(rc == FD_QUIC_PARSE_FAIL)) {
    return 1;
  }

  cur_ptr += rc;
  cur_sz -= rc;

  rc = fd_quic_encode_ip4(cur_ptr, cur_sz, pkt.ip4);
  if (FD_UNLIKELY(rc == FD_QUIC_PARSE_FAIL)) {
    return 1;
  }

  /* Compute checksum over network byte order header */
  fd_ip4_hdr_t *ip4_encoded = (fd_ip4_hdr_t *)fd_type_pun(cur_ptr);
  ip4_encoded->check = (ushort)fd_ip4_hdr_check_fast(ip4_encoded);

  cur_ptr += rc;
  cur_sz -= rc;

  rc = fd_quic_encode_udp(cur_ptr, cur_sz, pkt.udp);
  if (FD_UNLIKELY(rc == FD_QUIC_PARSE_FAIL)) {
    return 1;
  }

  cur_ptr += rc;
  cur_sz -= rc;

  if (pkt_type == FD_QUIC_PKTTYPE_V1_INITIAL || pkt_type == FD_QUIC_PKTTYPE_V1_HANDSHAKE) {
    fd_quic_pkt_hdr_t pkt_hdr;
    if (pkt_type == FD_QUIC_PKTTYPE_V1_INITIAL) {
      pkt_hdr.enc_level = fd_quic_enc_level_initial_id;
      fd_quic_initial_t *initial = &pkt_hdr.quic_pkt.initial;
      initial->hdr_form = 1;
      initial->fixed_bit = 1;
      initial->long_packet_type = 0;
      initial->reserved_bits = 0;
      initial->pkt_number_len = 3;
      initial->version = 1;
      initial->dst_conn_id_len = 8;
      initial->src_conn_id_len = 5;
      initial->token_len = 0;
      initial->len = payload_sz;
      initial->pkt_num = 0;
      initial->pkt_num_bits = 4 * 8;  /* actual number of bits to encode */

      // Print the values of the struct members for debugging
      //printf("hdr_form: %u\n", initial->hdr_form);
      //printf("fixed_bit: %u\n", initial->fixed_bit);
      //printf("long_packet_type: %u\n", initial->long_packet_type);
      //printf("reserved_bits: %u\n", initial->reserved_bits);
      //printf("pkt_number_len: %u\n", initial->pkt_number_len);
      //printf("version: %u\n", initial->version);
      //printf("dst_conn_id_len: %u\n", initial->dst_conn_id_len);
      //printf("src_conn_id_len: %u\n", initial->src_conn_id_len);
      //printf("token_len: %lu\n", initial->token_len);
      //printf("len: %lu\n", initial->len);
      //printf("pkt_num: %lu\n", initial->pkt_num);
      // Generate or hardcode the connection IDs
      memcpy(initial->dst_conn_id, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
      memcpy(initial->src_conn_id, "\x88\x77\x66\x55\x44", 5);

      // ulong initial_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, fd_quic_enc_level_initial_id );
      //padding
      uint initial_pkt = 1;
      uint base_pkt_len = (uint)cur_sz + fd_quic_pkt_hdr_pkt_number_len( &pkt_hdr, fd_quic_enc_level_initial_id ) +
                            FD_QUIC_CRYPTO_TAG_SZ;

      uint padding      = initial_pkt ? FD_QUIC_INITIAL_PAYLOAD_SZ_MIN - base_pkt_len : 0u;
      if( base_pkt_len + padding < ( FD_QUIC_CRYPTO_SAMPLE_SZ + FD_QUIC_CRYPTO_TAG_SZ ) ) {
        padding = FD_QUIC_CRYPTO_SAMPLE_SZ + FD_QUIC_CRYPTO_TAG_SZ - base_pkt_len;

      }

      //size calcs
      uint quic_pkt_len = base_pkt_len + padding;

      fd_quic_pkt_hdr_set_payload_sz( &pkt_hdr, fd_quic_enc_level_initial_id, quic_pkt_len );
      ulong act_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, fd_quic_enc_level_initial_id );
      // cur_ptr += (initial_hdr_sz + 3u - act_hdr_sz);
      // printf("advanced cur_ptr by initial_hdr_sz + 3u - act_hdr_sz: %lu\n", (initial_hdr_sz + 3u - act_hdr_sz));
    ulong rc = fd_quic_pkt_hdr_encode( cur_ptr, act_hdr_sz, &pkt_hdr, fd_quic_enc_level_initial_id );
    if (FD_UNLIKELY(rc == FD_QUIC_PARSE_FAIL)) {
      return 1;
    }

    cur_ptr += rc;
    cur_sz -= rc;
    }
    else { //handle handshake 
      pkt_hdr.enc_level = fd_quic_enc_level_handshake_id;
      // ulong hdr_sz = fd_quic_pkt_hdr_encode(cur_ptr, cur_sz, &pkt_hdr, pkt_hdr.enc_level); //TODO do this for the fuzz case when appropriate
    }
  }// end handshake/initial packet creation.

  if (FD_UNLIKELY((ulong)payload_sz > cur_sz)) {
    return FD_QUIC_FAILED;
  }
  //finally copy our junk into the packets
  //TODO this is where you would put a CRYPTO frame if so inclined for an Initial packet
  fd_memcpy(cur_ptr, payload, (ulong)payload_sz);

  cur_ptr += (ulong)payload_sz;
  cur_sz -= (ulong)payload_sz;
  
  fd_aio_pkt_info_t batch = {.buf = (void *)scratch,
                             .buf_sz = (ushort)(scratch_sz - cur_sz)};
  fd_quic_aio_cb_receive((void *)server_quic, &batch, 1, NULL, 0);

  return FD_QUIC_SUCCESS;
}

void 
init_quic(void) {
  void *ctx = (void *)0x1234UL;
  void *shaio = fd_aio_new(_aio, ctx, test_aio_send_func);
  assert( shaio );
  fd_aio_t *aio = fd_aio_join(shaio);
  assert(aio);

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  fd_quic_set_aio_net_tx(server_quic, aio);
  fd_quic_init( server_quic );
}

void
destroy_quic( void ) {
  fd_quic_fini( server_quic );
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  /* Set up shell without signal handlers */
  putenv("FD_LOG_BACKTRACE=0");
  fd_boot(argc, argv);
  atexit(fd_halt);

  /* Use unoptimized wksp memory */

  ulong wksp_sz = 13107200UL;

  uchar * mem = aligned_alloc( 4096UL, wksp_sz );
  assert( mem );

  ulong part_max = fd_wksp_part_max_est( wksp_sz, 64UL<<10 );
  assert( part_max );
  ulong data_max = fd_wksp_data_max_est( wksp_sz, 64UL<<10 );

  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 42U, part_max, data_max ) );
  assert( wksp );

  int shmem_err = fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, 4096UL, wksp_sz/4096UL );
  assert( !shmem_err );

  fd_quic_limits_t const quic_limits = {.conn_cnt = 10,
                                        .conn_id_cnt = 10,
                                        .conn_id_sparsity = 4.0,
                                        .handshake_cnt = 10,
                                        .stream_cnt = {0, 0, 10, 0},
                                        .initial_stream_cnt = {0, 0, 10, 0 },
                                        .stream_pool_cnt = 20,
                                        .inflight_pkt_cnt = 1024,
                                        .tx_buf_sz = 1 << 14};

  ulong quic_footprint = fd_quic_footprint(&quic_limits);
  assert( quic_footprint );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  server_quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng);
  assert( server_quic );
  fd_rng_delete( fd_rng_leave( rng ) );

  fd_quic_config_t *server_config = &server_quic->config;
  server_config->idle_timeout = 5e6;
  server_config->retry = 1;

  server_quic->cb.now = test_clock;
  server_quic->cb.now_ctx = NULL;

  server_quic->config.initial_rx_max_stream_data = 1 << 14;
  // server_quic->config.retry = 1;

  return 0;
}

int LLVMFuzzerTestOneInput(uchar const *data, ulong size) {
  ulong s = size;
  uchar const *ptr = data;

  init_quic();

  // Send initial packet
  send_packet(data, size, FD_QUIC_PKTTYPE_V1_INITIAL);

  // // Send handshake packet
    send_packet(data, size, FD_QUIC_PKTTYPE_V1_HANDSHAKE);

  while (s > 2) {
    FD_FUZZ_MUST_BE_COVERED;
    ushort payload_sz = (ushort)( ptr[0] + ( ptr[1] << 8u ) );
    ptr += 2;
    s -= 2;
    if (payload_sz <= s) {
      send_packet(ptr, payload_sz, 0);
      FD_FUZZ_MUST_BE_COVERED;
      ptr += payload_sz;
      s -= payload_sz;
    } else {
      FD_FUZZ_MUST_BE_COVERED;
      fd_quic_fini(server_quic);
      return 0;
    }
  }

  fd_quic_fini(server_quic);

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
