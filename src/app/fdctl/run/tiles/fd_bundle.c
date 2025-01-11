#define _DEFAULT_SOURCE
#include "../../../../disco/tiles.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <fcntl.h>
#include "generated/bundle_seccomp.h"

#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/keyguard/fd_keyguard.h"
#include "../../../../disco/keyguard/fd_keyguard_client.h"
#include "../../../../disco/plugin/fd_plugin.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../util/net/fd_ip4.h"

#include "fd_verify.h"

#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

typedef struct {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_bundle_out_ctx_t;

/* fd_bundle_ctx_t is the context object provided to callbacks from the
   mux tile, and contains all state needed to progress the tile. */

typedef struct {
  fd_keyguard_client_t keyguard_client[1];

  uchar identity_public_key[ 32UL ];

  ulong bundle_id;

  int plugin_initialized;

  char url[ 256 ];
  char domain_name[ 256 ];

  void * plugin;

  fd_bundle_out_ctx_t verify_out;
  fd_bundle_out_ctx_t plugin_out;

  struct {
    ulong txn_received;
    ulong bundle_received;
    ulong packet_received;
  } metrics;
} fd_bundle_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_bundle_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bundle_ctx_t ), sizeof( fd_bundle_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_bundle_ctx_t * ctx ) {
  FD_MCNT_SET( BUNDLE, TRANSACTION_RECEIVED, ctx->metrics.txn_received );
  FD_MCNT_SET( BUNDLE, BUNDLE_RECEIVED, ctx->metrics.bundle_received );
  FD_MCNT_SET( BUNDLE, PACKET_RECEIVED, ctx->metrics.packet_received );
}

extern void
plugin_bundle_poll( void *  plugin,
                    int *   out_type,
                    uchar * out_block_builder_pubkey,
                    ulong * out_block_builder_commission,
                    ulong * out_bundle_len,
                    uchar * out_data );

extern void *
plugin_bundle_init( char const * url,
                    char const * domain_name,
                    uchar *      identity_pubkey );

static FD_TL fd_bundle_ctx_t * tl_bundle_ctx;

void
plugin_bundle_sign_challenge( char const * challenge,
                              uchar *      out_signature ) {
  fd_bundle_ctx_t * ctx = tl_bundle_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, out_signature, (const uchar *)challenge, 9UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );
}

struct fd_bundle_msg {
   ulong      txn_cnt;
   fd_txn_p_t txns[ 5 ];
};

typedef struct fd_bundle_msg fd_bundle_msg_t;

static inline void
after_credit( fd_bundle_ctx_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( !ctx->plugin_initialized ) ) {
    ctx->plugin_initialized = 1;

    if( FD_LIKELY( ctx->plugin_out.mem ) ) {
      fd_plugin_msg_block_engine_update_t * update = (fd_plugin_msg_block_engine_update_t *)fd_chunk_to_laddr( ctx->plugin_out.mem, ctx->plugin_out.chunk );
      strncpy( update->url, ctx->url, sizeof(update->url) );
      strncpy( update->name, "jito", sizeof(update->name) );
      update->status = FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_DISCONNECTED;

      ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, ctx->plugin_out.idx, FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE, ctx->plugin_out.chunk, sizeof(fd_plugin_msg_block_engine_update_t), 0UL, 0UL, tspub );
      ctx->plugin_out.chunk = fd_dcache_compact_next( ctx->plugin_out.chunk, sizeof(fd_plugin_msg_block_engine_update_t), ctx->plugin_out.chunk0, ctx->plugin_out.wmark );

      return;
    }
  }

  fd_bundle_msg_t * msg = fd_chunk_to_laddr( ctx->verify_out.mem, ctx->verify_out.chunk );
  uchar data[ 5UL*(8UL+FD_TXN_MTU) ];

  int   type;
  ulong block_builder_commission;
  uchar block_builder_pubkey[ 32UL ];

  plugin_bundle_poll( ctx->plugin, &type, block_builder_pubkey, &block_builder_commission, &msg->txn_cnt, data );
  if( FD_LIKELY( !type ) ) return;

  *charge_busy = 1;

  if( FD_UNLIKELY( type<0 ) ) {
    if( FD_LIKELY( ctx->plugin_out.mem ) ) {
      fd_plugin_msg_block_engine_update_t * update = (fd_plugin_msg_block_engine_update_t *)fd_chunk_to_laddr( ctx->plugin_out.mem, ctx->plugin_out.chunk );
      strncpy( update->url, ctx->url, sizeof(update->url) );
      strncpy( update->name, "jito", sizeof(update->name) );

      switch( type ) {
        case -1: {
          update->status = FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_DISCONNECTED;
          break;
        }
        case -2: {
          update->status = FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTING;
          break;
        }
        case -3: {
          update->status = FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_CONNECTED;
          break;
        }
        default:
          FD_LOG_ERR(( "invalid plugin_bundle_poll return value %d", type ));
      }

      ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
      fd_stem_publish( stem, ctx->plugin_out.idx, FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE, ctx->plugin_out.chunk, sizeof(fd_plugin_msg_block_engine_update_t), 0UL, 0UL, tspub );
      ctx->plugin_out.chunk = fd_dcache_compact_next( ctx->plugin_out.chunk, sizeof(fd_plugin_msg_block_engine_update_t), ctx->plugin_out.chunk0, ctx->plugin_out.wmark );
    }
    return;
  }

  if( FD_UNLIKELY( !msg->txn_cnt ) ) return;

  if( FD_UNLIKELY( msg->txn_cnt>5UL ) ) {
    FD_LOG_WARNING(( "bundle plugin produced invalid bundle of length %lu", msg->txn_cnt ));
    return;
  }
  if( FD_UNLIKELY( block_builder_commission>100UL ) ) {
    FD_LOG_WARNING(( "bundle plugin produced invalid commission %lu", block_builder_commission ));
    return;
  }

  ulong offset = 0UL;
  for( ulong i=0UL; i<msg->txn_cnt; i++ ) {
    ulong payload_sz = fd_ulong_load_8( data+offset );
    if( FD_UNLIKELY( payload_sz>FD_TXN_MTU ) ) {
      FD_LOG_WARNING(( "bundle plugin produced invalid payload size %lu", payload_sz ));
      return;
    }
    offset += 8UL+payload_sz;
  }

  ctx->metrics.txn_received += msg->txn_cnt;
  if( FD_LIKELY( type==2 ) ) ctx->metrics.packet_received++;
  else                       ctx->metrics.bundle_received++;

  ctx->bundle_id = ctx->bundle_id+1UL;
  if( FD_UNLIKELY( !ctx->bundle_id ) ) ctx->bundle_id = 1UL;

  offset = 0UL;
  for( ulong i=0UL; i<msg->txn_cnt; i++ ) {
    ulong payload_sz = fd_ulong_load_8( data+offset );
    offset += 8UL;
    uchar const * payload = data+offset;
    offset += payload_sz;

    fd_txn_m_t * txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->verify_out.mem, ctx->verify_out.chunk );

    if( FD_LIKELY( type==2 ) ) txnm->block_engine.bundle_id = 0UL;
    else                       txnm->block_engine.bundle_id = ctx->bundle_id;

    if( FD_LIKELY( i ) ) {
      txnm->block_engine.bundle_txn_cnt = msg->txn_cnt;
      txnm->block_engine.commission = (uchar)block_builder_commission;
      fd_memcpy( txnm->block_engine.commission_pubkey, block_builder_pubkey, 32UL );
    } else {
      txnm->block_engine.bundle_txn_cnt = 0UL;
    }
    txnm->payload_sz = (ushort)payload_sz;
    fd_memcpy( fd_txn_m_payload( txnm ), payload, payload_sz );

    ulong footprint = fd_txn_m_realized_footprint( txnm, 0, 0 );

    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, ctx->verify_out.idx, 0UL, ctx->verify_out.chunk, footprint, 0UL, 0UL, tspub );
    ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, footprint, ctx->verify_out.chunk0, ctx->verify_out.wmark );
  }
}

static void
replace_domain_with_ip( char const * url,
                        char *       domain,
                        char *       result ) {
  const char * protocol_end = strstr( url, "://" );
  if( FD_UNLIKELY( !protocol_end ) ) FD_LOG_ERR(( "invalid [tiles.bundle.url] `%s`. Must start with `http[s]://`", url ));

  char const * domain_start = protocol_end+3UL;
  char const * domain_end = strchr( domain_start, ':' );
  if( FD_UNLIKELY( !domain_end ) ) domain_end = url + strlen( url );

  ulong domain_len = (ulong)(domain_end-domain_start);
  strncpy( domain, domain_start, domain_len );
  domain[ domain_len ] = '\0';

  struct addrinfo hints, *res;
  memset( &hints, 0, sizeof(hints) );
  hints.ai_family = AF_INET;

  int err = getaddrinfo( domain, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "getaddrinfo `%s` failed (%d-%s)", domain, err, gai_strerror( err ) ));

  uint ip_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  FD_TEST( fd_cstr_printf_check( result, 256, NULL, "%.*s" FD_IP4_ADDR_FMT "%s", (int)(protocol_end-url+3L), url, FD_IP4_ADDR_FMT_ARGS( ip_addr ), domain_end ) );
  freeaddrinfo(res);
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bundle_ctx_t ), sizeof( fd_bundle_ctx_t ) );

  uchar const * public_key = fd_keyload_load( tile->bundle.identity_key_path, 1 /* public key only */ );
  fd_memcpy( ctx->identity_public_key, public_key, 32UL );

  if( FD_UNLIKELY( strlen( tile->bundle.url)<8UL || (strncmp( "https://", tile->bundle.url, 8UL ) && strncmp( "http://", tile->bundle.url, 7UL ))  )) FD_LOG_ERR(( "invalid [tiles.bundle.url] `%s`. Must start with `http[s]://`", tile->bundle.url ));

  /* DNS resolution loads files, `resolv.conf` and all kind of rubbish
     like that, don't want to allow in the sandbox. */
  replace_domain_with_ip( tile->bundle.url, ctx->domain_name, ctx->url );
  if( FD_UNLIKELY( strcmp( tile->bundle.tls_domain_name, "" ) ) ) {
    strncpy( ctx->domain_name, tile->bundle.tls_domain_name, sizeof(ctx->domain_name) );
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

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

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
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bundle_ctx_t ), sizeof( fd_bundle_ctx_t ) );

  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_bundle", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ 1UL ] ];
  FD_TEST( !strcmp( sign_out->name, "bundle_sign" ) );

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                                     sign_out->mcache,
                                                                     sign_out->dcache,
                                                                     sign_in->mcache,
                                                                     sign_in->dcache ) ) ) ) {
    FD_LOG_ERR(( "fd_keyguard_client_join failed" ));
  }

  tl_bundle_ctx = ctx;

  ctx->plugin = plugin_bundle_init( ctx->url, ctx->domain_name, ctx->identity_public_key );
  FD_TEST( ctx->plugin );

  ctx->plugin_initialized = 0;
  ctx->bundle_id = 0UL;

  ctx->verify_out = out1( topo, tile, "bundle_verif" );
  ctx->plugin_out = out1opt( topo, tile, "bundle_plugi" );

  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_bundle( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_bundle_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (5UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_bundle_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_bundle_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_bundle = {
  .name                     = "bundle",
  .rlimit_file_cnt          = 4096UL, /* Rust side opens a few files for DNS lookups and things */
  .rlimit_address_space     = RLIM_INFINITY,
  .rlimit_data              = RLIM_INFINITY,
  .keep_host_networking     = 1,      /* We need to use the NIC to connect(2) to the block producer endpoint */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
