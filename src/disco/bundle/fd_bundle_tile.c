#include "fd_bundle_tile_private.h"
#include "../metrics/fd_metrics.h"
#include "../topo/fd_topo.h"
#include "../keyguard/fd_keyload.h"
#include "../../waltz/http/fd_url.h"

#include <errno.h>
#include <fcntl.h> /* F_SETFL */
#include <sys/uio.h> /* writev */
#include <netinet/in.h> /* AF_INET */
#include <netdb.h> /* getaddrinfo */

#include "generated/fd_bundle_tile_seccomp.h"

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
  return FD_LAYOUT_FINI( l, 32 );
}

static inline void
metrics_write( fd_bundle_tile_t * ctx ) {
  FD_MCNT_SET( BUNDLE, TRANSACTION_RECEIVED, ctx->metrics.txn_received_cnt    );
  FD_MCNT_SET( BUNDLE, BUNDLE_RECEIVED,      ctx->metrics.bundle_received_cnt );
  FD_MCNT_SET( BUNDLE, PACKET_RECEIVED,      ctx->metrics.packet_received_cnt );
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
after_credit( fd_bundle_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  if( FD_UNLIKELY( !ctx->stem ) ) ctx->stem = stem;
  fd_bundle_client_step( ctx, charge_busy );
}

static void
resolve_url( fd_url_t *   url_,
             char const * url_str,
             ulong        url_str_len,
             uint *       ip4_addr,
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

  struct addrinfo hints, *res;
  memset( &hints, 0, sizeof(hints) );
  hints.ai_family = AF_INET;

  int err = getaddrinfo( host_cstr, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "getaddrinfo `%s` failed (%d-%s)", host_cstr, err, gai_strerror( err ) ));
  }

  *ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  freeaddrinfo( res );
}

static void
fd_bundle_tile_resolve_endpoint( fd_bundle_tile_t *     ctx,
                                 fd_topo_tile_t const * tile ) {
  fd_url_t url[1];
  _Bool is_ssl = 0;
  resolve_url(
      url,
      tile->bundle.url, tile->bundle.url_len,
      &ctx->server_ip4_addr,
      &ctx->server_tcp_port,
      &is_ssl
  );
  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->server_fqdn ), url->host, url->host_len ) );
  ctx->server_fqdn_len = url->host_len;

# if FD_HAS_OPENSSL
  ctx->is_ssl = !!is_ssl;
# else
  if( FD_UNLIKELY( is_ssl ) ) {
    FD_LOG_ERR(( "This build does not include OpenSSL. To install OpenSSL, re-run ./deps.sh and do a clean re build." ));
  }
# endif
}

#if FD_HAS_OPENSSL

static void
fd_ossl_keylog_callback( SSL const *  ssl,
                         char const * line ) {
  SSL_CTX * ssl_ctx = SSL_get_SSL_CTX( ssl );
  fd_bundle_tile_t * ctx = SSL_CTX_get_ex_data( ssl_ctx, 0 );
  ulong line_len = strlen( line );
  struct iovec iovs[2] = {
    { .iov_base=(void *)line, .iov_len=line_len },
    { .iov_base=(void *)"\n", .iov_len=1UL }
  };
  if( FD_UNLIKELY( writev( ctx->keylog_fd, iovs, 2 )!=(long)line_len+1 ) ) {
    FD_LOG_WARNING(( "write(keylog) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
fd_bundle_tile_init_openssl( fd_bundle_tile_t * ctx ) {
  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
  if( FD_UNLIKELY( !ssl_ctx ) ) {
    FD_LOG_ERR(( "SSL_CTX_new failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_ex_data( ssl_ctx, 0, ctx ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_ex_data failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_mode( ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_mode failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_3_VERSION ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_min_proto_version(ssl_ctx,TLS1_3_VERSION) failed" ));
  }

  if( FD_UNLIKELY( 0!=SSL_CTX_set_alpn_protos( ssl_ctx, (const unsigned char *)"\x02h2", 3 ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_alpn_protos failed" ));
  }

  if( FD_LIKELY( ctx->keylog_fd >= 0 ) ) {
    SSL_CTX_set_keylog_callback( ssl_ctx, fd_ossl_keylog_callback );
  }

  ctx->ssl_ctx = ssl_ctx;
}

#endif /* FD_HAS_OPENSSL */

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_tile_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_bundle_tile_t), sizeof(fd_bundle_tile_t) );
  void *             grpc_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_client_align(), fd_grpc_client_footprint()  );
  ulong              scratch_end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( (ulong)ctx != (ulong)scratch ) ) {
    FD_LOG_CRIT(( "Invalid bundle tile scratch alignment" )); /* unreachable */
  }
  if( FD_UNLIKELY( scratch_end - (ulong)scratch > scratch_footprint( tile ) ) ) {
    FD_LOG_CRIT(( "Bundle tile scratch overflow" )); /* unreachable */
  }

  memset( ctx, 0, sizeof(fd_bundle_tile_t) );
  ctx->grpc_client_mem = grpc_mem;
  ctx->tcp_sock        = -1;

  fd_bundle_auther_init( &ctx->auther );
  uchar const * public_key = fd_keyload_load( tile->bundle.identity_key_path, 1 /* public key only */ );
  fd_memcpy( ctx->auther.pubkey, public_key, 32UL );

  /* DNS resolution does arbitrary syscalls and system ops, therefore
     has to be run outside the sandbox. */
  fd_bundle_tile_resolve_endpoint( ctx, tile );

  /* Override server name indication */
  if( FD_UNLIKELY( tile->bundle.sni_len ) ) {
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( ctx->server_fqdn ), tile->bundle.sni, tile->bundle.sni_len ) );
    ctx->server_fqdn_len = tile->bundle.sni_len;
  }

# if FD_HAS_OPENSSL

  ctx->keylog_fd = -1;
  if( FD_UNLIKELY( tile->bundle.key_log_path[0] ) ) {
    ctx->keylog_fd = open( tile->bundle.key_log_path, O_WRONLY|O_APPEND|O_CREAT, 0644 );
    if( FD_UNLIKELY( ctx->keylog_fd < 0 ) ) {
      FD_LOG_ERR(( "open(%s) failed (%i-%s)", tile->bundle.key_log_path, errno, fd_io_strerror( errno ) ));
    }
  }

  /* OpenSSL initialization does arbitrary syscalls and system ops,
     therefore has to be run outside the sandbox. */
  fd_bundle_tile_init_openssl( ctx );

# endif /* FD_HAS_OPENSSL */

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

static inline fd_bundle_out_ctx_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong  chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong  wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_bundle_out_ctx_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static inline fd_bundle_out_ctx_t
out1opt( fd_topo_t const *      topo,
         fd_topo_tile_t const * tile,
         char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    return (fd_bundle_out_ctx_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0UL, .wmark = 0UL, .chunk = 0UL };
  }

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_bundle_out_ctx_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_bundle_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_bundle", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ 1UL ] ];
  FD_TEST( !strcmp( sign_out->name, "bundle_sign" ) );

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

  ctx->verify_out = out1   ( topo, tile, "bundle_verif" );
  ctx->plugin_out = out1opt( topo, tile, "bundle_plugi" );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_bundle_tile(
      out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_bundle_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
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
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
