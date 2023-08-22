#include "fd_frank.h"

#include "../../disco/quic/fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../tango/xdp/fd_xsk_private.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>

#include <sys/xattr.h>
#include <linux/unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static void
init( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "loading %s", "xsk" ));
  args->xsk = fd_xsk_join( fd_wksp_pod_map( args->tile_pod, "xsk" ) );
  if( FD_UNLIKELY( !args->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  args->lo_xsk = NULL;
  if( FD_UNLIKELY( fd_pod_query_cstr( args->tile_pod, "lo_xsk", NULL ) ) ) {
    FD_LOG_INFO(( "loading %s", "lo_xsk" ));
    args->lo_xsk = fd_xsk_join( fd_wksp_pod_map( args->tile_pod, "lo_xsk" ) );
    if( FD_UNLIKELY( !args->lo_xsk ) ) FD_LOG_ERR(( "fd_xsk_join (lo) failed" ));
  }

  /* OpenSSL goes and tries to read files and allocate memory and
     other dumb things on a thread local basis, so we need a special
     initializer to do it before seccomp happens in the process. */
  ERR_STATE * state = ERR_get_state();
  if( FD_UNLIKELY( !state )) FD_LOG_ERR(( "ERR_get_state failed" ));
  if( FD_UNLIKELY( !OPENSSL_init_ssl( OPENSSL_INIT_LOAD_SSL_STRINGS , NULL ) ) )
    FD_LOG_ERR(( "OPENSSL_init_ssl failed" ));
  if( FD_UNLIKELY( !OPENSSL_init_crypto( OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_NO_LOAD_CONFIG , NULL ) ) )
    FD_LOG_ERR(( "OPENSSL_init_crypto failed" ));
}

struct fd_quic_tpu_ctx;

struct root_aio_ctx {
  ushort transaction_listen_port;
  ushort quic_transaction_listen_port;

  const fd_aio_t * quic_aio;
  void (*transaction_callback)( struct fd_quic_tpu_ctx * ctx, uchar const * packet, uint packet_sz );
};

static int
root_aio_net_rx( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {
  struct root_aio_ctx * root_ctx = ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    uchar const * packet = batch[i].buf;
    uchar const * packet_end = packet + batch[i].buf_sz;

    uchar const * iphdr = packet + 14U;

    /* Filter for UDP/IPv4 packets.
      Test for ethtype and ipproto in 1 branch */
    uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
    if( FD_UNLIKELY( test_ethip!=0x080011 ) )
      FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                   "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                   "is not configured correctly." ));

    /* IPv4 is variable-length, so lookup IHL to find start of UDP */
    uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
    uchar const * udp = iphdr + iplen;

    /* Ignore if UDP header is too short */
    if( FD_UNLIKELY( udp+4U > packet_end ) ) continue;

    /* Extract IP dest addr and UDP dest port */
    ulong ip_dstaddr  = *(uint   *)( iphdr+16UL );
    (void)ip_dstaddr;
    ushort udp_dstport = *(ushort *)( udp+2UL    );

    uchar const * data = udp + 8U;
    uint data_sz = (uint)(packet_end - data);

    ulong ignored;
    if( FD_LIKELY( fd_ushort_bswap( udp_dstport ) == root_ctx->quic_transaction_listen_port ) )
      root_ctx->quic_aio->send_func( root_ctx->quic_aio->ctx, batch + i, 1, &ignored, flush );
    else if( FD_LIKELY( fd_ushort_bswap( udp_dstport ) == root_ctx->transaction_listen_port ) )
      root_ctx->transaction_callback( root_ctx->quic_aio->ctx, data, data_sz );
    else
      FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                  "Only ports %hu and %hu should be configured to forward packets. Do "
                  "you need to reload the XDP program?",
                  fd_ushort_bswap( udp_dstport ), root_ctx->transaction_listen_port, root_ctx->quic_transaction_listen_port ));
  }

  /* the assumption here at present is that any packet that could not be processed
     is simply dropped hence, all packets were consumed */
  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

extern void
fd_quic_transaction_receive( struct fd_quic_tpu_ctx * ctx,
                             uchar const *       packet,
                             uint                packet_sz );

static void
run( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "quic.%lu init", args->idx ));

  /* Join the IPC objects needed by this tile instance */

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  cnc_diag[ FD_FRANK_CNC_DIAG_PID ] = (ulong)args->pid;

  FD_LOG_INFO(( "joining mcache%lu", args->tile_idx ));
  char path[ 32 ];
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( args->out_pod, path ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining dcache" ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( args->extra_pod, path ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "loading quic" ));
  fd_quic_t * quic = fd_quic_join( fd_wksp_pod_map( args->tile_pod, "quic" ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  FD_LOG_INFO(( "loading xsk_aio" ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( args->tile_pod, "xsk_aio" ), args->xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));

  fd_xsk_aio_t * lo_xsk_aio = NULL;
  if( FD_UNLIKELY( args->lo_xsk ) ) {
    FD_LOG_INFO(( "loading lo xsk_aio" ));
    lo_xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( args->tile_pod, "lo_xsk_aio" ), args->lo_xsk );
    if( FD_UNLIKELY( !lo_xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));
  }

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( args->tile_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( args->tile_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( args->tile_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( args->tile_pod, "lazy",      0L  );
  FD_LOG_INFO(( "cr_max    %lu", cr_max    ));
  FD_LOG_INFO(( "cr_resume %lu", cr_resume ));
  FD_LOG_INFO(( "cr_refill %lu", cr_refill ));
  FD_LOG_INFO(( "lazy      %li", lazy      ));

  uint seed = fd_pod_query_uint( args->tile_pod, "dedup.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  FD_LOG_INFO(( "creating scratch" ));
  ulong footprint = fd_quic_tile_scratch_footprint( fd_mcache_depth( mcache ) );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_quic_tile_scratch_footprint failed" ));
  void * scratch = fd_alloca( FD_QUIC_TILE_SCRATCH_ALIGN, footprint );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Configure QUIC server */

  fd_quic_config_t * quic_cfg = &quic->config;
  quic_cfg->role = FD_QUIC_ROLE_SERVER;

  char const * keylog_file = fd_pod_query_cstr( args->tile_pod, "keylog_file", NULL ); /* optional */

  strncpy( quic_cfg->keylog_file, keylog_file ? keylog_file : "", FD_QUIC_CERT_PATH_LEN );

  /* TODO read IP addresses from interface instead? */
  quic_cfg->net.ip_addr = fd_pod_query_uint( args->tile_pod, "ip_addr", 0 );
  if( FD_UNLIKELY( !quic_cfg->net.ip_addr ) ) FD_LOG_ERR(( "ip_addr not set" ));

  /* TODO read MAC address from interface instead? */
  const void * src_mac = fd_pod_query_buf( args->tile_pod, "src_mac_addr", NULL );
  if( FD_UNLIKELY( !src_mac ) ) FD_LOG_ERR(( "src_mac_addr not set" ));
  fd_memcpy( quic_cfg->link.src_mac_addr, src_mac, 6 );

  ushort transaction_listen_port = fd_pod_query_ushort( args->tile_pod, "transaction_listen_port", 0 );
  if( FD_UNLIKELY( !transaction_listen_port ) ) FD_LOG_ERR(( "transaction_listen_port not set" ));

  ushort quic_transaction_listen_port = fd_pod_query_ushort( args->tile_pod, "quic_transaction_listen_port", 0 );
  if( FD_UNLIKELY( !quic_transaction_listen_port ) ) FD_LOG_ERR(( "quic_transaction_listen_port not set" ));
  quic_cfg->net.listen_udp_port = quic_transaction_listen_port;

  ulong idle_timeout_ms = fd_pod_query_ulong( args->tile_pod, "idle_timeout_ms", 0 );
  if( FD_UNLIKELY( !idle_timeout_ms ) ) FD_LOG_ERR(( "idle_timeout_ms not set" ));
  quic_cfg->idle_timeout = idle_timeout_ms * 1000000UL;

  ulong initial_rx_max_stream_data = fd_pod_query_ulong( args->tile_pod, "initial_rx_max_stream_data", 1<<15 );
  if( FD_UNLIKELY( !initial_rx_max_stream_data ) ) FD_LOG_ERR(( "initial_rx_max_stream_data not set" ));
  quic_cfg->initial_rx_max_stream_data = initial_rx_max_stream_data;

  /* Attach to XSK */

  const fd_aio_t * quic_aio = fd_quic_get_aio_net_rx( quic );

  struct root_aio_ctx root_ctx = {
    .quic_aio = quic_aio,
    .transaction_callback = fd_quic_transaction_receive,
    .transaction_listen_port = transaction_listen_port,
    .quic_transaction_listen_port = quic_transaction_listen_port,
  };

  fd_aio_t root_aio = {
    .ctx       = &root_ctx,
    .send_func = root_aio_net_rx,
  };

  if( FD_UNLIKELY( lo_xsk_aio) ) fd_xsk_aio_set_rx( lo_xsk_aio, &root_aio );
  fd_xsk_aio_set_rx     ( xsk_aio,    &root_aio );
  fd_quic_set_aio_net_tx( quic,       fd_xsk_aio_get_tx( xsk_aio ) );

  /* Start serving */

  FD_LOG_INFO(( "%s(%lu) run", args->tile_name, args->tile_idx ));
  int err = fd_quic_tile( cnc, quic, xsk_aio, lo_xsk_aio, mcache, dcache, lazy, rng, scratch, args->tick_per_ns );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_quic_tile failed (%i)", err ));
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_getpid,    /* OpenSSL RAND_bytes checks pid, temporarily used as part of quic_init to generate a certificate */
  __NR_getrandom, /* OpenSSL RAND_bytes reads getrandom, temporarily used as part of quic_init to generate a certificate */
  __NR_madvise,   /* OpenSSL SSL_do_handshake () uses an arena which eventually calls _rjem_je_pages_purge_forced */
  __NR_sendto,    /* fd_xsk requires sendto */
};

static ulong
allow_fds( fd_frank_args_t * args,
           ulong             out_fds_sz,
           int *             out_fds ) {
  if( FD_UNLIKELY( out_fds_sz < 4 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  out_fds[ 2 ] = args->xsk->xsk_fd;
  out_fds[ 3 ] = args->lo_xsk ? args->lo_xsk->xsk_fd : -1;
  return args->lo_xsk ? 4 : 3;
}

fd_frank_task_t frank_quic = {
  .name              = "quic",
  .in_wksp           = NULL,
  .out_wksp          = "quic_verify",
  .extra_wksp        = "tpu_txn_data",
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = init,
  .run               = run,
};
