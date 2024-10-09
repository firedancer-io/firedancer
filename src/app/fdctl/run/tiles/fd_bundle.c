#define _DEFAULT_SOURCE
#include "../../../../disco/tiles.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include "generated/bundle_seccomp.h"

#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/keyguard/fd_keyguard.h"
#include "../../../../disco/keyguard/fd_keyguard_client.h"
#include "../../../../util/net/fd_ip4.h"

#include "fd_verify.h"

#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

/* fd_bundle_ctx_t is the context object provided to callbacks from the
   mux tile, and contains all state needed to progress the tile. */

typedef struct {
  fd_sha512_t * sha[ FD_TXN_ACTUAL_SIG_MAX ];

  fd_keyguard_client_t * keyguard_client;

  uchar identity_public_key[ 32UL ];

  char url[ 256 ];
  char domain_name[ 256 ];

  void * plugin;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
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
  for( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_sha512_align(), fd_sha512_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_bundle_ctx_t ) );
}

extern void
plugin_bundle_poll( void *  plugin,
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

static void
after_credit( void *             _ctx,
              fd_mux_context_t * mux,
              int *              opt_poll_in ) {
  (void)opt_poll_in;

  fd_bundle_ctx_t * ctx = (fd_bundle_ctx_t *)_ctx;

  fd_bundle_msg_t * msg = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  uchar data[ 5UL*(8UL+FD_TXN_MTU) ];

  plugin_bundle_poll( ctx->plugin, msg->block_builder_pubkey, &msg->block_builder_commission, &msg->txn_cnt, data );
  if( FD_UNLIKELY( !msg->txn_cnt ) ) return;
  if( FD_UNLIKELY( msg->txn_cnt>5UL ) ) {
    FD_LOG_WARNING(( "bundle plugin produced invalid bundle of length %lu", msg->txn_cnt ));
    return;
  }

  ulong offset = 0UL;
  for( ulong i=0UL; i<msg->txn_cnt; i++ ) {
    ulong payload_sz = fd_ulong_load_8( data+offset );
    offset += 8UL;

    if( FD_UNLIKELY( payload_sz>FD_TXN_MTU ) ) {
      FD_LOG_WARNING(( "bundle plugin produced invalid txn payload of length %lu", payload_sz ));
      return;
    }

    fd_txn_p_t * txn = &msg->txns[ i ];

    txn->payload_sz = (ushort)payload_sz;
    fd_memcpy( txn->payload, data+offset, payload_sz );
    offset += payload_sz;

    fd_txn_t * txn_t = TXN( txn );
    ulong txn_t_sz = fd_txn_parse( txn->payload, payload_sz, txn_t, NULL );
    if( FD_UNLIKELY( !txn_t_sz ) ) {
      FD_LOG_WARNING(( "bundle plugin produced invalid txn failed to parse" ));
      return;
    }

    uchar  signature_cnt = txn_t->signature_cnt;
    ushort signature_off = txn_t->signature_off;
    ushort acct_addr_off = txn_t->acct_addr_off;
    ushort message_off   = txn_t->message_off;

    uchar const * signatures = txn->payload + signature_off;
    uchar const * pubkeys = txn->payload + acct_addr_off;
    uchar const * msg = txn->payload + message_off;
    ulong msg_sz = (ulong)payload_sz - message_off;

    int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
    if( FD_UNLIKELY( res!=FD_ED25519_SUCCESS ) ) {
      FD_LOG_WARNING(( "Bundle plugin produced invalid txn verify failed" ));
      return;
    }

    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mux_publish( mux, 0, ctx->out_chunk, sizeof( fd_bundle_msg_t ), 0UL, 0UL, tspub );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof( fd_bundle_msg_t ), ctx->out_chunk0, ctx->out_wmark );
  }
}

static void
replace_domain_with_ip( char const * url,
                        char *       domain,
                        char *       result ) {
  const char * protocol_end = strstr( url, "://" );
  if( FD_UNLIKELY( !protocol_end ) ) FD_LOG_ERR(( "invalid [tiles.bundle.url] `%s`. Must start with `https://`", url ));

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
privileged_init( FD_PARAM_UNUSED fd_topo_t *      topo,
                 FD_PARAM_UNUSED fd_topo_tile_t * tile,
                 void *                           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bundle_ctx_t ), sizeof( fd_bundle_ctx_t ) );

  uchar const * public_key = fd_keyload_load( tile->bundle.identity_key_path, 1 /* public key only */ );
  fd_memcpy( ctx->identity_public_key, public_key, 32UL );

  if( FD_UNLIKELY( strlen( tile->bundle.url)<8UL || strncmp( "https://", tile->bundle.url, 8UL ) )) FD_LOG_ERR(( "invalid [tiles.bundle.url] `%s`. Must start with `https://`", tile->bundle.url ));

  /* DNS resolution loads files, `resolv.conf` and all kind of rubbish
     like that, don't want to allow in the sandbox. */
  replace_domain_with_ip( tile->bundle.url, ctx->domain_name, ctx->url );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bundle_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bundle_ctx_t ), sizeof( fd_bundle_ctx_t ) );

  tl_bundle_ctx = ctx;

  for( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[ i ] = sha;
  }

  ctx->plugin = plugin_bundle_init( ctx->url, ctx->domain_name, ctx->identity_public_key );
  FD_TEST( ctx->plugin );

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_bundle( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_bundle_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_bundle = {
  .name                     = "bundle",
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .keep_host_networking     = 1,      /* We need to use the NIC to connect(2) to the block producer endpoint */
  .rlimit_file_cnt          = 4096UL, /* Rust side opens a few files for DNS lookups and things */
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
