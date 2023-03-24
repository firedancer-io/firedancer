#include "fd_frank.h"

#include "../../disco/quic/fd_quic.h"
#include "../../util/net/fd_eth.h"

int
fd_frank_quic_task( int     argc,
                    char ** argv ) {
  if( FD_UNLIKELY( argc!=3 ) )
    FD_LOG_ERR(( "unexpected arguments to tile" ));

  char const * tile_name = argv[0];
  fd_log_thread_set( tile_name );
  FD_LOG_INFO(( "%s init", tile_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path %s not found", cfg_path ));

  uchar const * quic_pod = fd_pod_query_subpod( cfg_pod, tile_name );
  if( FD_UNLIKELY( !quic_pod ) ) FD_LOG_ERR(( "path %s.%s not found", cfg_pod, tile_name ));

  /* Join the IPC objects needed by this tile instance */

  FD_LOG_INFO(( "joining %s.%s.cnc", cfg_path, tile_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( quic_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  FD_LOG_INFO(( "joining %s.%s.mcache", cfg_path, tile_name ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( quic_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining %s.%s.dcache", cfg_path, tile_name ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( quic_pod, "dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "joining %s.%s.quic", cfg_path, tile_name ));
  fd_quic_t * quic = fd_quic_join( fd_wksp_pod_map( quic_pod, "quic" ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  /* Load the QUIC config */

  uchar const * tls_pod = fd_pod_query_subpod( cfg_pod, "tls" );
  if( FD_UNLIKELY( !tls_pod ) ) FD_LOG_ERR(( "path %s.tls not found", cfg_path ));

  char const * tls_cert_path = fd_pod_query_cstr( tls_pod, "cert-file", NULL );
  char const * tls_key_path  = fd_pod_query_cstr( tls_pod, "key_file",  NULL );
  if( FD_UNLIKELY( !tls_cert_path ) ) FD_LOG_ERR(( "missing %s.tls.cert-file", cfg_path ));
  if( FD_UNLIKELY( !tls_key_path  ) ) FD_LOG_ERR(( "missing %s.tls.key-file",  cfg_path ));

  char const * tls_keylog_path = fd_pod_query_cstr( tls_pod, "keylog-file", NULL );
  if( tls_keylog_path ) FD_LOG_INFO(( "Logging TLS keys to %s", tls_keylog_path ));

  /* Build the QUIC config object */

  fd_quic_config_t quic_cfg = {0};
  strncpy( quic_cfg.cert_file, tls_cert_path, PATH_MAX-1UL );
  strncpy( quic_cfg.key_file,  tls_key_path,  PATH_MAX-1UL );
  if( tls_keylog_path )
    strncpy( quic_cfg.keylog_file, tls_keylog_path, PATH_MAX-1UL );

  /* Read QUIC params */
  /* FIXME: Most of these params are already constants set pre-join */

  quic_cfg.max_concur_conns       = fd_pod_query_ulong( quic_pod, "max-concur-conns",      0UL  );
  quic_cfg.max_concur_conn_ids    = fd_pod_query_ulong( quic_pod, "max-concur-conn-ids",   0UL  );
  quic_cfg.max_concur_streams     = fd_pod_query_uint ( quic_pod, "max-concur-streams",    0U   );
  quic_cfg.max_concur_handshakes  = fd_pod_query_uint ( quic_pod, "max-concur-handshakes", 0U   );
  quic_cfg.conn_id_sparsity       = fd_pod_query_ulong( quic_pod, "conn-id-sparsity",      0UL  );
  quic_cfg.max_in_flight_pkts     = fd_pod_query_ulong( quic_pod, "max-in-flight-pkts",    0UL  );
  quic_cfg.max_in_flight_acks     = fd_pod_query_ulong( quic_pod, "max-in-flight-acks",    0UL  );
  quic_cfg.mean_time_between_svc  = fd_pod_query_ulong( quic_pod, "mean-time-between-svc", 0UL  );
  quic_cfg.dscp            = (uchar)fd_pod_query_uint ( quic_pod, "dscp",                  0U   );

  /* Read network params */

  uchar const * net_pod = fd_pod_query_subpod( cfg_pod, "net" );
  if( FD_UNLIKELY( !net_pod ) ) FD_LOG_ERR(( "path %s.net not found", cfg_path ));

  char const * _default_route_mac = fd_pod_query_cstr  ( net_pod, "gateway-mac-addr", "" );
  char const * _src_mac           = fd_pod_query_cstr  ( net_pod, "mac-addr",         "" );
  char const * _ip_addr           = fd_pod_query_cstr  ( net_pod, "ip-addr",          "" );
  quic_cfg.host_cfg.udp_port      = fd_pod_query_ushort( net_pod, "udp-port",         0U );

  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _default_route_mac, quic_cfg.net.default_route_mac ) ) )
    FD_LOG_ERR(( "invalid gateway-mac-addr" ));
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _src_mac,           quic_cfg.net.src_mac           ) ) )
    FD_LOG_ERR(( "invalid mac-addr" ));
  if( FD_UNLIKELY( quic_cfg.host_cfg.udp_port==0U ) )
    FD_LOG_ERR(( "missing udp-port" ));

  ulong ip_addr = fd_cstr_to_ip4_addr( _ip_addr );
  if( FD_UNLIKELY( ip_addr==ULONG_MAX ) ) FD_LOG_ERR(( "invalid ip-addr \"%s\"", _ip_addr ));
  quic_cfg.host_cfg.ip_addr = (uint)ip_addr;

  /* Setup local objects used by this tile */

  ulong orig = fd_pod_query_ulong( quic_pod, "orig", ULONG_MAX );
  if( FD_UNLIKELY( orig==ULONG_MAX ) ) FD_LOG_ERR(( "missing %s.%s.orig", cfg_path, tile_name ));

  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( quic_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( quic_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( quic_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( quic_pod, "lazy",      0L  );
  FD_LOG_INFO(( "%s.%s.cr_max    %lu", cfg_path, tile_name, cr_max    ));
  FD_LOG_INFO(( "%s.%s.cr_resume %lu", cfg_path, tile_name, cr_resume ));
  FD_LOG_INFO(( "%s.%s.cr_refill %lu", cfg_path, tile_name, cr_refill ));
  FD_LOG_INFO(( "%s.%s.lazy      %li", cfg_path, tile_name, lazy      ));

  uint seed = fd_pod_query_uint( cfg_pod, "dedup.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.dedup.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  FD_LOG_INFO(( "creating scratch" ));
  ulong footprint = fd_quic_tile_scratch_footprint( fd_mcache_depth( mcache ) );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_quic_tile_scratch_footprint failed" ));
  void * scratch = fd_alloca( FD_QUIC_TILE_SCRATCH_ALIGN, footprint );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Start serving */

  FD_LOG_INFO(( "%s run", tile_name ));
  int err = fd_quic_tile( cnc, orig, quic, &quic_cfg, mcache, dcache, lazy, rng, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_quic_tile failed (%i)", err ));

  /* Clean up */

  FD_LOG_INFO(( "%s fini", tile_name ));
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  fd_wksp_pod_unmap( fd_quic_leave  ( quic   ) );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod );
  return 0;
}
