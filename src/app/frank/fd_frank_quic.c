#include "fd_frank.h"

#include "../../disco/quic/fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>

#include <linux/unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_futex,     /* logging, glibc fprintf unfortunately uses a futex internally */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_nanosleep, /* fd_tempo_tick_per_ns calibration */
  __NR_getpid,    /* OpenSSL RAND_bytes checks pid, temporarily used as part of quic_init to generate a certificate */
  __NR_getrandom, /* OpenSSL RAND_bytes reads getrandom, temporarily used as part of quic_init to generate a certificate */
};

static void
init( fd_frank_args_t * args ) {
  args->pod = fd_wksp_pod_attach( args->pod_gaddr );
  args->close_fd_start = 4; /* stdin, stdout, stderr, logfile */
  args->allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]);
  args->allow_syscalls = allow_syscalls;

  char quic_xsk[ 32 ];
  snprintf( quic_xsk, 32, "firedancer.quic.quic%lu.xsk", args->idx );

  FD_LOG_INFO(( "loading %s", quic_xsk ));
  args->xsk = fd_xsk_join( fd_wksp_pod_map( args->pod, quic_xsk ) );
  if( FD_UNLIKELY( !args->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

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

static void
run( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "quic.%lu init", args->idx ));

  /* Load up the configuration for this frank instance */

  uchar const * cfg_pod = fd_pod_query_subpod( args->pod, "firedancer" );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path firedancer not found" ));

  uchar const * quic_pods = fd_pod_query_subpod( cfg_pod, "quic" );
  if( FD_UNLIKELY( !quic_pods ) ) FD_LOG_ERR(( "firedancer.quic path not found" ));

  char quic_name[ 32 ];
  snprintf( quic_name, 32, "quic%lu", args->idx );
  uchar const * quic_pod = fd_pod_query_subpod( quic_pods, quic_name );
  if( FD_UNLIKELY( !quic_pod ) ) FD_LOG_ERR(( "firedancer.quic.%s path not found", quic_name ));

  uchar const * quic_cfg_pod = fd_pod_query_subpod( cfg_pod, "quic_cfg" );
  if( FD_UNLIKELY( !quic_cfg_pod ) ) FD_LOG_ERR(( "firedancer.quic_cfg path not found" ));

  /* Join the IPC objects needed by this tile instance */

  FD_LOG_INFO(( "joining firedancer.quic.%s.cnc", quic_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( quic_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  FD_LOG_INFO(( "joining firedancer.quic.%s.mcache", quic_name ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( quic_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining firedancer.quic.%s.dcache", quic_name ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( quic_pod, "dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "loading firedancer.quic.%s.quic", quic_name ));
  fd_quic_t * quic = fd_quic_join( fd_wksp_pod_map( quic_pod, "quic" ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  FD_LOG_INFO(( "loading firedancer.quic.%s.xsk_aio", quic_name ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( quic_pod, "xsk_aio" ), args->xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));

  /* Setup local objects used by this tile */

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( quic_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( quic_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( quic_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( quic_pod, "lazy",      0L  );
  FD_LOG_INFO(( "firedancer.quic.%s.cr_max    %lu", quic_name, cr_max    ));
  FD_LOG_INFO(( "firedancer.quic.%s.cr_resume %lu", quic_name, cr_resume ));
  FD_LOG_INFO(( "firedancer.quic.%s.cr_refill %lu", quic_name, cr_refill ));
  FD_LOG_INFO(( "firedancer.quic.%s.lazy      %li", quic_name, lazy      ));

  uint seed = fd_pod_query_uint( cfg_pod, "dedup.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (firedancer.dedup.seed %u)", seed ));
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

  char const * keylog_file = fd_pod_query_cstr( quic_cfg_pod, "keylog_file", NULL ); /* optional */

  strncpy( quic_cfg->keylog_file, keylog_file ? keylog_file : "", FD_QUIC_CERT_PATH_LEN );

  /* TODO read IP addresses from interface instead? */
  quic_cfg->net.ip_addr = fd_pod_query_uint( quic_cfg_pod, "ip_addr", 0 );
  if( FD_UNLIKELY( !quic_cfg->net.ip_addr ) ) FD_LOG_ERR(( "firedancer.quic_cfg.ip_addr not set" ));

  /* TODO read MAC address from interface instead? */
  const void * src_mac = fd_pod_query_buf( quic_cfg_pod, "src_mac_addr", NULL );
  if( FD_UNLIKELY( !src_mac ) ) FD_LOG_ERR(( "firedancer.quic_cfg.src_mac_addr not set" ));
  fd_memcpy( quic_cfg->link.src_mac_addr, src_mac, 6 );

  ushort listen_port = fd_pod_query_ushort( quic_cfg_pod, "listen_port", 0 );
  if( FD_UNLIKELY( !listen_port ) ) FD_LOG_ERR(( "firedancer.quic_cfg.listen_port not set" ));
  quic_cfg->net.listen_udp_port = listen_port;

  ulong idle_timeout_ms = fd_pod_query_ulong( quic_cfg_pod, "idle_timeout_ms", 0 );
  if( FD_UNLIKELY( !idle_timeout_ms ) ) FD_LOG_ERR(( "firedancer.quic_cfg.idle_timeout_ms not set" ));
  quic_cfg->idle_timeout = idle_timeout_ms * 1000000UL;

  ulong initial_rx_max_stream_data = fd_pod_query_ulong( quic_cfg_pod, "initial_rx_max_stream_data", 1<<15 );
  if( FD_UNLIKELY( !initial_rx_max_stream_data ) ) FD_LOG_ERR(( "firedancer.quic_cfg.initial_rx_max_stream_data not set" ));
  quic_cfg->initial_rx_max_stream_data = initial_rx_max_stream_data;

  /* Attach to XSK */

  fd_xsk_aio_set_rx     ( xsk_aio, fd_quic_get_aio_net_rx( quic    ) );
  fd_quic_set_aio_net_tx( quic,    fd_xsk_aio_get_tx     ( xsk_aio ) );

  /* Start serving */

  FD_LOG_INFO(( "%s run", quic_name ));
  int err = fd_quic_tile( cnc, quic, xsk_aio, mcache, dcache, lazy, rng, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_quic_tile failed (%i)", err ));
}

fd_frank_task_t quic = {
  .name = "quic",
  .init = init,
  .run  = run,
};
