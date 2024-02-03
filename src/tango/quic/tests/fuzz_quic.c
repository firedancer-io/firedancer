#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

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

#include "../../../ballet/x509/fd_x509_mock.h"

fd_quic_t *server_quic = NULL;

uchar scratch[0x4000];
size_t scratch_sz = 0x4000;

fd_aio_t _aio[1];


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

uint send_packet(uchar const *payload, size_t payload_sz) {

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

  if (FD_UNLIKELY((ulong)payload_sz > cur_sz)) {
    return FD_QUIC_FAILED;
  }
  fd_memcpy(cur_ptr, payload, (ulong)payload_sz);

  cur_ptr += (ulong)payload_sz;
  cur_sz -= (ulong)payload_sz;

  fd_aio_pkt_info_t batch = {.buf = (void *)scratch,
                             .buf_sz = (ushort)(scratch_sz - cur_sz)};

  fd_quic_aio_cb_receive((void *)server_quic, &batch, 1, NULL, 0);

  return FD_QUIC_SUCCESS; /* success */
}

void init_quic(void) {
  void *ctx = (void *)0x1234UL;
  void *shaio = fd_aio_new(_aio, ctx, test_aio_send_func);
  FD_TEST(shaio);
  fd_aio_t *aio = fd_aio_join(shaio);
  FD_TEST(aio);

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

  ulong cpu_idx = fd_tile_cpu_id(fd_tile_idx());
  if (cpu_idx > fd_shmem_cpu_cnt())
    cpu_idx = 0UL;

  char const *_page_sz =
      fd_env_strip_cmdline_cstr(argc, argv, "--page-sz", NULL, "normal");
  ulong page_cnt =
      fd_env_strip_cmdline_ulong(argc, argv, "--page-cnt", NULL, 3200UL);
  ulong numa_idx = fd_env_strip_cmdline_ulong(argc, argv, "--numa-idx", NULL,
                                              fd_shmem_numa_idx(cpu_idx));

  ulong page_sz = fd_cstr_to_shmem_page_sz(_page_sz);
  if (FD_UNLIKELY(!page_sz))
    FD_LOG_ERR(("unsupported --page-sz"));

  fd_wksp_t *wksp = fd_wksp_new_anonymous(
      page_sz, page_cnt, fd_shmem_cpu_idx(numa_idx), "wksp", 0UL);
  FD_TEST(wksp);

  fd_quic_limits_t const quic_limits = {.conn_cnt = 10,
                                        .conn_id_cnt = 10,
                                        .conn_id_sparsity = 4.0,
                                        .handshake_cnt = 10,
                                        .stream_cnt = {0, 0, 10, 0},
                                        .inflight_pkt_cnt = 1024,
                                        .tx_buf_sz = 1 << 14};

  ulong quic_footprint = fd_quic_footprint(&quic_limits);
  FD_TEST(quic_footprint);

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  server_quic = fd_quic_new_anonymous(wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng);
  FD_TEST(server_quic);
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

  while (s > 2) {
    FD_FUZZ_MUST_BE_COVERED;
    ushort payload_sz = (ushort)( ptr[0] + ( ptr[1] << 8u ) );
    ptr += 2;
    s -= 2;
    if (payload_sz <= s) {
      send_packet(ptr, payload_sz);
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
