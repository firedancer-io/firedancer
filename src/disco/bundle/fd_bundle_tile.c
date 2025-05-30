#include "fd_bundle_tile_private.h"
#include "../metrics/fd_metrics.h"
#include "../topo/fd_topo.h"
#include "../keyguard/fd_keyload.h"
#include "../plugin/fd_plugin.h"
#include "../../waltz/http/fd_url.h"

#include <errno.h>
#include <stdio.h> /* snprintf */
#include <fcntl.h> /* F_SETFL */
#include <sys/mman.h> /* PROT_READ (seccomp) */
#include <sys/uio.h> /* writev */
#include <netinet/in.h> /* AF_INET */
#include <netinet/tcp.h> /* TCP_FASTOPEN_CONNECT (seccomp) */
#include "../../waltz/resolv/fd_netdb.h"

#include "generated/fd_bundle_tile_seccomp.h"

#if FD_HAS_MBEDTLS
#include "../../waltz/mbedtls/fd_mbedtls.h"
#include <mbedtls/ssl.h>
#endif

FD_FN_CONST static ulong
scratch_align( void ) {
  return alignof(fd_bundle_tile_t);
}

FD_FN_CONST static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_bundle_tile_t), sizeof(fd_bundle_tile_t)   );
  l = FD_LAYOUT_APPEND( l, fd_grpc_client_align(),    fd_grpc_client_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),          fd_alloc_footprint()       );
  return FD_LAYOUT_FINI( l, 32 );
}

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for MbedTLS allocations */
  return 1UL<<26; /* 64 MiB */
}

static inline void
metrics_write( fd_bundle_tile_t * ctx ) {
  FD_MCNT_SET( BUNDLE, TRANSACTION_RECEIVED,   ctx->metrics.txn_received_cnt          );
  FD_MCNT_SET( BUNDLE, BUNDLE_RECEIVED,        ctx->metrics.bundle_received_cnt       );
  FD_MCNT_SET( BUNDLE, PACKET_RECEIVED,        ctx->metrics.packet_received_cnt       );
  FD_MCNT_SET( BUNDLE, SHREDSTREAM_HEARTBEATS, ctx->metrics.shredstream_heartbeat_cnt );
  FD_MCNT_SET( BUNDLE, KEEPALIVES,             ctx->metrics.ping_ack_cnt              );
  FD_MCNT_SET( BUNDLE, ERRORS_PROTOBUF,        ctx->metrics.decode_fail_cnt           );
  FD_MCNT_SET( BUNDLE, ERRORS_TRANSPORT,       ctx->metrics.transport_fail_cnt        );
  FD_MCNT_SET( BUNDLE, ERRORS_NO_FEE_INFO,     ctx->metrics.missing_builder_info_fail_cnt );

  fd_wksp_t * wksp = fd_wksp_containing( ctx );
  fd_wksp_usage_t usage[1];
  ulong const free_tag = 0UL;
  if( FD_UNLIKELY( !fd_wksp_usage( wksp, &free_tag, 1UL, usage ) ) ) {
    FD_LOG_ERR(( "fd_wksp_usage failed" )); /* unreachable */
  }
  FD_MGAUGE_SET( BUNDLE, HEAP_SIZE,       usage->total_sz );
  FD_MGAUGE_SET( BUNDLE, HEAP_FREE_BYTES, usage->used_sz  );

  int bundle_status = fd_bundle_client_status( ctx );
  FD_MGAUGE_SET( BUNDLE, CONNECTED, bundle_status==FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTED );
  ctx->bundle_status_recent = (uchar)bundle_status;
}

static void
during_housekeeping( fd_bundle_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ctx->identity_switched = 1;
    fd_memcpy( ctx->auther.pubkey, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
fd_bundle_tile_publish_block_engine_update(
    fd_bundle_tile_t *  ctx,
    fd_stem_context_t * stem
) {
  fd_plugin_msg_block_engine_update_t * update =
      fd_chunk_to_laddr( ctx->plugin_out.mem, ctx->plugin_out.chunk );
  memset( update, 0, sizeof(fd_plugin_msg_block_engine_update_t) );

  strncpy( update->name, "jito", sizeof(update->name) );

  /* Deliberately silently truncates */
  snprintf( update->url, sizeof(update->url), "%s://%.*s:%u",
            ctx->is_ssl ? "https" : "http",
            (int)ctx->server_fqdn_len,
            ctx->server_fqdn,
            ctx->server_tcp_port );

  /* Format IPv4 string */
  snprintf( update->ip_cstr, sizeof(update->ip_cstr),
            FD_IP4_ADDR_FMT,
            FD_IP4_ADDR_FMT_ARGS( ctx->server_ip4_addr ) );

  update->status = (uchar)ctx->bundle_status_recent;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish(
      stem,
      ctx->plugin_out.idx,
      FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE,
      ctx->plugin_out.chunk,
      sizeof(fd_plugin_msg_block_engine_update_t),
      0UL, /* ctl */
      0UL, /* seq */
      tspub
  );
  ctx->plugin_out.chunk = fd_dcache_compact_next( ctx->plugin_out.chunk, sizeof(fd_plugin_msg_block_engine_update_t), ctx->plugin_out.chunk0, ctx->plugin_out.wmark );
}

static void
after_credit( fd_bundle_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  if( FD_UNLIKELY( !ctx->stem ) ) ctx->stem = stem;
  fd_bundle_client_step( ctx, charge_busy );

  if( ctx->plugin_out.mem ) {
    if( FD_UNLIKELY( ctx->bundle_status_recent != ctx->bundle_status_plugin ) ) {
      fd_bundle_tile_publish_block_engine_update( ctx, stem );
      ctx->bundle_status_plugin = (uchar)ctx->bundle_status_recent;
      *charge_busy = 1;
    }
  }
}

static void
parse_url( fd_url_t *   url_,
           char const * url_str,
           ulong        url_str_len,
           ushort *     tcp_port,
           _Bool *      is_ssl ) {

  /* Parse URL */

  int url_err[1];
  fd_url_t * url = fd_url_parse_cstr( url_, url_str, url_str_len, url_err );
  if( FD_UNLIKELY( !url ) ) {
    switch( *url_err ) {
    scheme_err:
    case FD_URL_ERR_SCHEME:
      FD_LOG_ERR(( "Invalid [tiles.bundle.url] `%.*s`: must start with `http://` or `https://`", (int)url_str_len, url_str ));
      break;
    case FD_URL_ERR_HOST_OVERSZ:
      FD_LOG_ERR(( "Invalid [tiles.bundle.url] `%.*s`: domain name is too long", (int)url_str_len, url_str ));
      break;
    default:
      FD_LOG_ERR(( "Invalid [tiles.bundle.url] `%.*s`", (int)url_str_len, url_str ));
      break;
    }
  }

  /* FIXME the URL scheme path technically shouldn't contain slashes */
  if( url->scheme_len==8UL && fd_memeq( url->scheme, "https://", 8UL ) ) {
    *is_ssl = 1;
  } else if( url->scheme_len==7UL && fd_memeq( url->scheme, "http://", 7UL ) ) {
    *is_ssl = 0;
  } else {
    goto scheme_err;
  }

  /* Parse port number */

  *tcp_port = 443;
  if( url->port_len ) {
    if( FD_UNLIKELY( url->port_len > 5 ) ) {
    invalid_port:
      FD_LOG_ERR(( "Invalid [tiles.bundle.url] `%.*s`: invalid port number", (int)url_str_len, url_str ));
    }

    char port_cstr[6];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( port_cstr ), url->port, url->port_len ) );
    ulong port_no = fd_cstr_to_ulong( port_cstr );
    if( FD_UNLIKELY( !port_no || port_no>USHORT_MAX ) ) goto invalid_port;

    *tcp_port = (ushort)port_no;
  }

  /* Resolve domain */

  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  char host_cstr[ 256 ];
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( host_cstr ), url->host, url->host_len ) );
}

static void
fd_bundle_tile_parse_endpoint( fd_bundle_tile_t *     ctx,
                               fd_topo_tile_t const * tile ) {
  fd_url_t url[1];
  _Bool is_ssl = 0;
  parse_url(
      url,
      tile->bundle.url, tile->bundle.url_len,
      &ctx->server_tcp_port,
      &is_ssl
  );
  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->server_fqdn ), url->host, url->host_len ) );
  ctx->server_fqdn_len = url->host_len;

  if( FD_UNLIKELY( tile->bundle.sni_len ) ) {
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->server_sni ), tile->bundle.sni, tile->bundle.sni_len ) );
    ctx->server_sni_len = tile->bundle.sni_len;
  } else {
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->server_sni ), url->host, url->host_len ) );
    ctx->server_sni_len = url->host_len;
  }

  ctx->is_ssl = !!is_ssl;
#if !FD_HAS_MBEDTLS
  if( FD_UNLIKELY( is_ssl ) ) {
    FD_LOG_ERR(( "This build does not include MbedTLS. To install MbedTLS, re-run ./deps.sh and do a clean re build." ));
  }
#endif
}

#if FD_HAS_MBEDTLS

static void
unprivileged_init_mbedtls( fd_bundle_tile_t * ctx ) {
  FD_LOG_DEBUG(( "Setting up mbedtls_entropy" ));
  mbedtls_entropy_init( &ctx->tls_entropy );

  FD_LOG_DEBUG(( "Setting up mbedtls_ctr_drbg" ));
  mbedtls_ctr_drbg_init( &ctx->tls_ctr_drbg );
  if( FD_UNLIKELY( 0!=mbedtls_ctr_drbg_seed(
      &ctx->tls_ctr_drbg,
      mbedtls_entropy_func,
      &ctx->tls_entropy,
      (uchar const *)"bundle", /* entropy "personalization" string */
      sizeof("bundle")
  ) ) ) {
    FD_LOG_ERR(( "mbedtls_ctr_drbg_seed failed" ));
  }

  FD_LOG_DEBUG(( "Setting up mbedtls_ssl_config" ));
  mbedtls_ssl_config * ssl_conf = &ctx->tls_config;
  mbedtls_ssl_config_init( ssl_conf );
  if( FD_UNLIKELY( 0!=mbedtls_ssl_config_defaults(
      ssl_conf,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT
  ) ) ) {
    FD_LOG_ERR(( "mbedtls_ssl_config_defaults failed" ));
  }
  mbedtls_ssl_conf_min_tls_version( ssl_conf, MBEDTLS_SSL_VERSION_TLS1_3 );
  mbedtls_ssl_conf_max_tls_version( ssl_conf, MBEDTLS_SSL_VERSION_TLS1_3 );
  mbedtls_ssl_conf_rng            ( ssl_conf, mbedtls_ctr_drbg_random, &ctx->tls_ctr_drbg );
  mbedtls_ssl_conf_authmode       ( ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED );
  mbedtls_ssl_conf_ca_chain       ( ssl_conf, &ctx->tls_ca_certs, NULL );

  static char const * alpn_protos[] = { "h2", NULL };
  if( FD_UNLIKELY( 0!=mbedtls_ssl_conf_alpn_protocols( &ctx->tls_config, alpn_protos ) ) ) {
    FD_LOG_ERR(( "mbedtls_ssl_conf_alpn_protocols failed" ));
  }

  FD_LOG_DEBUG(( "MbedTLS initialized" ));
}

#endif /* FD_HAS_MBEDTLS */

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_tile_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_bundle_tile_t), sizeof(fd_bundle_tile_t)   );
  void *             grpc_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_client_align(),    fd_grpc_client_footprint() );
  void *             alloc_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),          fd_alloc_footprint()       );
  ulong              scratch_end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_end - (ulong)scratch > scratch_footprint( tile ) ) ) {
    FD_LOG_CRIT(( "Bundle tile scratch overflow" )); /* unreachable */
  }
  if( FD_UNLIKELY( (ulong)ctx != (ulong)scratch ) ) {
    FD_LOG_CRIT(( "Invalid bundle tile scratch alignment" )); /* unreachable */
  }
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );
  ctx->grpc_client_mem = grpc_mem;

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR(( "fd_alloc_new failed" ));
  }
  ctx->ssl_alloc = alloc;
  fd_mbedtls_set_alloc( ctx->ssl_alloc );

  ctx->tcp_sock = -1;

  fd_bundle_auther_init( &ctx->auther );
  uchar const * public_key = fd_keyload_load( tile->bundle.identity_key_path, 1 /* public key only */ );
  fd_memcpy( ctx->auther.pubkey, public_key, 32UL );

  ctx->keylog_fd = -1;

# if FD_HAS_MBEDTLS

  if( FD_UNLIKELY( tile->bundle.key_log_path[0] ) ) {
    ctx->keylog_fd = open( tile->bundle.key_log_path, O_WRONLY|O_APPEND|O_CREAT, 0644 );
    if( FD_UNLIKELY( ctx->keylog_fd < 0 ) ) {
      FD_LOG_ERR(( "open(%s) failed (%i-%s)", tile->bundle.key_log_path, errno, fd_io_strerror( errno ) ));
    }
  }

  mbedtls_x509_crt_init( &ctx->tls_ca_certs );
  mbedtls_x509_crt_parse_path( &ctx->tls_ca_certs, "/etc/ssl/certs/" );

# endif /* FD_HAS_MBEDTLS */

  /* Init resolver */
  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) {
    FD_LOG_ERR(( "fd_netdb_open_fds failed" ));
  }

  /* Random seed for header hashmap */
  if( FD_UNLIKELY( !fd_rng_secure( &ctx->map_seed, sizeof(ulong) ) ) ) {
    FD_LOG_CRIT(( "fd_rng_secure failed" ));
  }

  /* Random seed for timing RNG */
  uint rng_seed;
  if( FD_UNLIKELY( !fd_rng_secure( &rng_seed, sizeof(uint) ) ) ) {
    FD_LOG_CRIT(( "fd_rng_secure failed" ));
  }
  if( FD_UNLIKELY( !fd_rng_join( fd_rng_new( &ctx->rng, rng_seed, 0UL ) ) ) ) {
    FD_LOG_CRIT(( "fd_rng_join failed" )); /* unreachable */
  }
}

static fd_bundle_out_ctx_t
bundle_out_link( fd_topo_t const *      topo,
                 fd_topo_link_t const * link,
                 ulong                  out_link_idx ) {
  fd_bundle_out_ctx_t out = {0};
  out.idx    = out_link_idx;
  out.mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  out.chunk0 = fd_dcache_compact_chunk0( out.mem, link->dcache );
  out.wmark  = fd_dcache_compact_wmark ( out.mem, link->dcache, link->mtu );
  out.chunk  = out.chunk0;
  return out;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    FD_LOG_ERR(( "There can only be one bundle tile" ));
  }

  fd_bundle_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_bundle", tile->kind_id );
  if( FD_UNLIKELY( sign_in_idx==ULONG_MAX ) ) FD_LOG_ERR(( "Missing sign_bundle link" ));
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id[ sign_in_idx ] ];

  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "bundle_sign", tile->kind_id );
  if( FD_UNLIKELY( sign_out_idx==ULONG_MAX ) ) FD_LOG_ERR(( "Missing bundle_sign link" ));
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new(
      ctx->keyguard_client,
      sign_out->mcache,
      sign_out->dcache,
      sign_in->mcache,
      sign_in->dcache
  ) ) ) ) {
    FD_LOG_ERR(( "fd_keyguard_client_join failed" )); /* unreachable */
  }

  ctx->identity_switched = 0;
  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong verify_out_idx = fd_topo_find_tile_out_link( topo, tile, "bundle_verif", tile->kind_id );
  if( FD_UNLIKELY( verify_out_idx==ULONG_MAX ) ) FD_LOG_ERR(( "Missing bundle_verif link" ));
  ctx->verify_out = bundle_out_link( topo, &topo->links[ tile->out_link_id[ verify_out_idx ] ], verify_out_idx );

  ulong plugin_out_idx = fd_topo_find_tile_out_link( topo, tile, "bundle_plugi", tile->kind_id );
  if( plugin_out_idx!=ULONG_MAX ) {
    ctx->plugin_out = bundle_out_link( topo, &topo->links[ tile->out_link_id[ plugin_out_idx ] ], plugin_out_idx );
  } else {
    ctx->plugin_out = (fd_bundle_out_ctx_t){ .idx=ULONG_MAX };
  }

  /* Set socket receive buffer size */
  ulong so_rcvbuf = tile->bundle.buf_sz;
  if( FD_UNLIKELY( so_rcvbuf < 2048UL  ) ) FD_LOG_ERR(( "Invalid [development.bundle.buffer_size_kib]: too small" ));
  if( FD_UNLIKELY( so_rcvbuf > INT_MAX ) ) FD_LOG_ERR(( "Invalid [development.bundle.buffer_size_kib]: too large" ));
  ctx->so_rcvbuf = (int)so_rcvbuf;

  /* Set idle ping timer */
  ctx->ping_threshold_ticks = fd_ulong_pow2_up( (ulong)
      ( (double)tile->bundle.keepalive_interval_nanos * fd_tempo_tick_per_ns( NULL ) ) );
  ctx->ping_randomize = fd_rng_ulong( ctx->rng );

  /* Force tile to output a plugin message on startup */
  ctx->bundle_status_plugin = 127;
  ctx->bundle_status_recent = FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_DISCONNECTED;

  fd_bundle_tile_parse_endpoint( ctx, tile );

# if FD_HAS_MBEDTLS
  unprivileged_init_mbedtls( ctx );
# endif
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_bundle_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_bundle_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->keylog_fd,
      (uint)ctx->netdb_fds->etc_hosts,
      (uint)ctx->netdb_fds->etc_resolv_conf
  );
  return sock_filter_policy_fd_bundle_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_bundle_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts >= 0 ) )
    out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  if( FD_UNLIKELY( ctx->keylog_fd>=0 ) )
    out_fds[ out_cnt++ ] = ctx->keylog_fd;
  return out_cnt;
}

#define STEM_BURST (5UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_bundle_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_bundle_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_bundle = {
  .name                     = "bundle",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .rlimit_file_cnt          = 64,
  .keep_host_networking     = 1
};
