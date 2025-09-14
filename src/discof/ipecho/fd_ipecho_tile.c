#include "fd_ipecho_client.h"
#include "fd_ipecho_server.h"
#include "genesis_hash.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "generated/fd_ipecho_tile_seccomp.h"

struct fd_ipecho_tile_ctx {
  int retrieving;

  fd_ipecho_server_t * server;
  fd_ipecho_client_t * client;

  uint   bind_address;
  ushort bind_port;

  ushort bootstrap_shred_version;
  ushort expected_shred_version;
  ushort shred_version;
};

typedef struct fd_ipecho_tile_ctx fd_ipecho_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_ipecho_tile_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_ipecho_tile_ctx_t ), sizeof( fd_ipecho_tile_ctx_t )       );
  l = FD_LAYOUT_APPEND( l, fd_ipecho_client_align(),        fd_ipecho_client_footprint()         );
  l = FD_LAYOUT_APPEND( l, fd_ipecho_server_align(),        fd_ipecho_server_footprint( 1024UL ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_ipecho_tile_ctx_t * ctx ) {
  fd_ipecho_server_metrics_t * metrics = fd_ipecho_server_metrics( ctx->server );

  FD_MGAUGE_SET( IPECHO, CONNECTION_COUNT,         metrics->connection_cnt        );
  FD_MCNT_SET(   IPECHO, BYTES_READ,               metrics->bytes_read            );
  FD_MCNT_SET(   IPECHO, BYTES_WRITTEN,            metrics->bytes_written         );
  FD_MCNT_SET(   IPECHO, CONNECTIONS_CLOSED_OK,    metrics->connections_closed_ok );
  FD_MCNT_SET(   IPECHO, CONNECTIONS_CLOSED_ERROR, metrics->connections_closed_error );
}

static inline void
poll_client( fd_ipecho_tile_ctx_t * ctx,
             fd_stem_context_t *    stem,
             int *                  charge_busy ) {
  if( FD_UNLIKELY( !ctx->client ) ) {
    FD_LOG_NOTICE(( "using expected shred version %hu", ctx->shred_version ));
    FD_MGAUGE_SET( IPECHO, SHRED_VERSION, ctx->shred_version );
    fd_stem_publish( stem, 0UL, ctx->shred_version, 0UL, 0UL, 0UL, 0UL, 0UL );
    ctx->retrieving = 0;
    fd_ipecho_server_init( ctx->server, ctx->bind_address, ctx->bind_port, ctx->shred_version );
    return;
  }

  int result = fd_ipecho_client_poll( ctx->client, &ctx->shred_version, charge_busy );
  if( FD_UNLIKELY( !result ) ) {
    if( FD_UNLIKELY( ctx->expected_shred_version && ctx->expected_shred_version!=ctx->shred_version ) ) {
      FD_LOG_ERR(( "Expected shred version %hu but entrypoint returned %hu",
                   ctx->expected_shred_version, ctx->shred_version ));
    }

    FD_LOG_INFO(( "retrieved shred version %hu from entrypoint", ctx->shred_version ));
    FD_MGAUGE_SET( IPECHO, SHRED_VERSION, ctx->shred_version );
    fd_stem_publish( stem, 0UL, ctx->shred_version, 0UL, 0UL, 0UL, 0UL, 0UL );
    fd_ipecho_server_init( ctx->server, ctx->bind_address, ctx->bind_port, ctx->shred_version );
    ctx->retrieving = 0;
    return;
  } else if( FD_UNLIKELY( -1==result ) ) {
    FD_LOG_ERR(( "Could not determine shred version from entrypoints.  Please "
                 "check you can connect to the entrypoints provided." ));
  }
}

static inline void
after_credit( fd_ipecho_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in,
              int *                  charge_busy ) {
  (void)opt_poll_in;

  int timeout = ctx->retrieving ? 0 : 10;

  if( FD_UNLIKELY( ctx->retrieving ) ) poll_client( ctx, stem, charge_busy );
  else                                 fd_ipecho_server_poll( ctx->server, charge_busy, timeout );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_ipecho_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_ipecho_tile_ctx_t ), sizeof( fd_ipecho_tile_ctx_t ) );

  if( FD_UNLIKELY( !tile->ipecho.entrypoints_cnt ) ) {
    /* We are the bootstrap node, genesis.bin must already exist so
       compute shred version. */
    int result = compute_shred_version( tile->ipecho.genesis_path, &ctx->bootstrap_shred_version, NULL );
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_LIKELY( errno==ENOENT ) ) {
        FD_LOG_ERR(( "This node is bootstrapping the cluster as it has no gossip entrypoints provided, but "
                     "the genesis.bin file at `%s` does not exist.  Please provide a valid genesis.bin "
                     "file by running genesis, or join an existing cluster.",
                     tile->ipecho.genesis_path ));
      } else {
        FD_LOG_ERR(( "Could not compute shred version from genesis.bin file at `%s` (%i-%s)",
                     tile->ipecho.genesis_path, errno, fd_io_strerror( errno ) ));
      }
    }
    FD_TEST( ctx->bootstrap_shred_version );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_ipecho_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_ipecho_tile_ctx_t ), sizeof( fd_ipecho_tile_ctx_t )       );
  void * _client             = FD_SCRATCH_ALLOC_APPEND( l, fd_ipecho_client_align(),        fd_ipecho_client_footprint()         );
  void * _server             = FD_SCRATCH_ALLOC_APPEND( l, fd_ipecho_server_align(),        fd_ipecho_server_footprint( 1024UL ) );

  ctx->bind_address = tile->ipecho.bind_address;
  ctx->bind_port    = tile->ipecho.bind_port;

  ctx->expected_shred_version = tile->ipecho.expected_shred_version;
  ctx->shred_version = 0U;

  ctx->retrieving = 1;
  if( FD_LIKELY( tile->ipecho.entrypoints_cnt ) ) {
    ctx->client = fd_ipecho_client_join( fd_ipecho_client_new( _client ) );
    FD_TEST( ctx->client );
    fd_ipecho_client_init( ctx->client, tile->ipecho.entrypoints, tile->ipecho.entrypoints_cnt );
  } else {
    if( FD_UNLIKELY( tile->ipecho.expected_shred_version && (tile->ipecho.expected_shred_version!=ctx->bootstrap_shred_version ) ) ) {
      FD_LOG_ERR(( "This node is bootstrapping the cluster as it has no gossip entrypoints provided, but "
                   "a [consensus.expected_shred_version] of %hu is provided which does not match the shred "
                   "version of %hu computed from the genesis.bin file at `%s`",
                   tile->ipecho.expected_shred_version, ctx->bootstrap_shred_version, tile->ipecho.genesis_path ));
    }
    ctx->shred_version = ctx->bootstrap_shred_version;
    ctx->client = NULL;
  }

  ctx->server = fd_ipecho_server_join( fd_ipecho_server_new( _server, 1024UL ) );
  FD_TEST( ctx->server );

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

  populate_sock_filter_policy_fd_ipecho_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_ipecho_tile_instr_cnt;
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

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_ipecho_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_ipecho_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_ipecho = {
  .name                     = "ipecho",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
