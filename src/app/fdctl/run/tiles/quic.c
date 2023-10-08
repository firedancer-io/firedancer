#include "tiles.h"
#include "../../fdctl.h"
#include "../run.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../tango/xdp/fd_xsk_private.h"

#include <linux/unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static void
init( fd_tile_args_t * args ) {
  (void)args;

  /* call wallclock so glibc loads VDSO, which requires calling mmap while
     privileged */
  fd_log_wallclock();

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE */
  fd_tempo_tick_per_ns( NULL );

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

static ushort
initialize_quic( fd_quic_config_t * config,
                 uchar const * pod ) {
  uint ip_addr = fd_pod_query_uint( pod, "ip_addr", 0 );
  if( FD_UNLIKELY( !ip_addr ) ) FD_LOG_ERR(( "ip_addr not set" ));

  const void * src_mac = fd_pod_query_buf( pod, "src_mac_addr", NULL );
  if( FD_UNLIKELY( !src_mac ) ) FD_LOG_ERR(( "src_mac_addr not set" ));

  ushort transaction_listen_port = fd_pod_query_ushort( pod, "transaction_listen_port", 0 );
  if( FD_UNLIKELY( !transaction_listen_port ) ) FD_LOG_ERR(( "transaction_listen_port not set" ));

  ushort quic_transaction_listen_port = fd_pod_query_ushort( pod, "quic_transaction_listen_port", 0 );
  if( FD_UNLIKELY( !quic_transaction_listen_port ) ) FD_LOG_ERR(( "quic_transaction_listen_port not set" ));

  ulong idle_timeout_ms = fd_pod_query_ulong( pod, "idle_timeout_ms", 0 );
  if( FD_UNLIKELY( !idle_timeout_ms ) ) FD_LOG_ERR(( "idle_timeout_ms not set" ));

  ulong initial_rx_max_stream_data = fd_pod_query_ulong( pod, "initial_rx_max_stream_data", 1<<15 );
  if( FD_UNLIKELY( !initial_rx_max_stream_data ) ) FD_LOG_ERR(( "initial_rx_max_stream_data not set" ));

  config->role = FD_QUIC_ROLE_SERVER;
  config->net.ip_addr = ip_addr;
  fd_memcpy( config->link.src_mac_addr, src_mac, 6 );
  config->net.listen_udp_port = quic_transaction_listen_port;
  config->idle_timeout = idle_timeout_ms * 1000000UL;
  config->initial_rx_max_stream_data = initial_rx_max_stream_data;

  return transaction_listen_port;
}

static void
run( fd_tile_args_t * args ) {
  const uchar * tile_pod = args->wksp_pod[ 0 ];
  const uchar * mux_pod  = args->wksp_pod[ 1 ];
  const uchar * out_pod  = args->wksp_pod[ 2 ];

  fd_quic_t * quic = fd_quic_join( fd_wksp_pod_map1( tile_pod, "quic%lu", args->tile_idx ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));
  ushort legacy_transaction_port = initialize_quic( &quic->config, tile_pod );

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map1( out_pod, "mcache%lu", args->tile_idx ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong depth = fd_mcache_depth( mcache );

  ulong cnt = fd_pod_query_ulong( mux_pod, "quic-cnt", 0UL );
  if( FD_UNLIKELY( !cnt ) ) FD_LOG_ERR(( "quic-cnt not set" ));

  fd_rng_t _rng[ 1 ];
  fd_quic_tile( fd_cnc_join( fd_wksp_pod_map1( tile_pod, "cnc%lu", args->tile_idx ) ),
                (ulong)args->pid,
                1,
                (const fd_frag_meta_t **)&(fd_frag_meta_t*){ fd_mcache_join( fd_wksp_pod_map( mux_pod, "mcache" ) ) },
                &(ulong*){ fd_fseq_join( fd_wksp_pod_map1( mux_pod, "quic-in-fseq%lu", args->tile_idx ) ) },
                cnt,
                args->tile_idx,
                fd_mcache_join( fd_wksp_pod_map1( mux_pod, "quic-out-mcache%lu", args->tile_idx ) ),
                fd_dcache_join( fd_wksp_pod_map1( mux_pod, "quic-out-dcache%lu", args->tile_idx ) ),
                quic,
                legacy_transaction_port,
                mcache,
                fd_dcache_join( fd_wksp_pod_map1( out_pod, "dcache%lu", args->tile_idx ) ),
                0,
                0,
                fd_rng_join( fd_rng_new( _rng, 0, 0UL ) ),
                fd_alloca( FD_QUIC_TILE_SCRATCH_ALIGN, fd_quic_tile_scratch_footprint( depth, 1, 1 ) ) );
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_getpid,    /* OpenSSL RAND_bytes checks pid, temporarily used as part of quic_init to generate a certificate */
  __NR_getrandom, /* OpenSSL RAND_bytes reads getrandom, temporarily used as part of quic_init to generate a certificate */
  __NR_madvise,   /* OpenSSL SSL_do_handshake() uses an arena which eventually calls _rjem_je_pages_purge_forced */
  __NR_mmap,      /* OpenSSL again... deep inside SSL_provide_quic_data() some jemalloc code calls mmap */
  __NR_rt_sigaction, /* allows a signal handler for SYSSIG - to debug syscalls */
  __NR_socket,       /* allows netlink to create sockets */
};

static workspace_kind_t allow_workspaces[] = {
  wksp_quic,         /* the tile itself */
  wksp_netmux_inout, /* sending / receiving packets from network */
  wksp_quic_verify,  /* send path for transactions */
};

static ulong
allow_fds( fd_tile_args_t * args,
           ulong            out_fds_sz,
           int *            out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 2 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t quic = {
  .name                 = "quic",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls       = allow_syscalls,
  .allow_fds            = allow_fds,
  .init                 = init,
  .run                  = run,
};
