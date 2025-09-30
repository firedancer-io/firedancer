#include "fd_ipecho_client.h"
#include "fd_ipecho_server.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>

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
  l = FD_LAYOUT_APPEND( l, alignof(fd_ipecho_tile_ctx_t), sizeof(fd_ipecho_tile_ctx_t)         );
  l = FD_LAYOUT_APPEND( l, fd_ipecho_client_align(),      fd_ipecho_client_footprint()         );
  l = FD_LAYOUT_APPEND( l, fd_ipecho_server_align(),      fd_ipecho_server_footprint( 1024UL ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_ipecho_tile_ctx_t * ctx ) {
  fd_ipecho_server_metrics_t * metrics = fd_ipecho_server_metrics( ctx->server );

  FD_MGAUGE_SET( IPECHO, CONNECTION_COUNT,         metrics->connection_cnt           );
  FD_MCNT_SET(   IPECHO, BYTES_READ,               metrics->bytes_read               );
  FD_MCNT_SET(   IPECHO, BYTES_WRITTEN,            metrics->bytes_written            );
  FD_MCNT_SET(   IPECHO, CONNECTIONS_CLOSED_OK,    metrics->connections_closed_ok    );
  FD_MCNT_SET(   IPECHO, CONNECTIONS_CLOSED_ERROR, metrics->connections_closed_error );
}

static inline void
poll_client( fd_ipecho_tile_ctx_t * ctx,
             fd_stem_context_t *    stem,
             int *                  charge_busy ) {
  if( FD_UNLIKELY( !ctx->client ) ) return;

  int result = fd_ipecho_client_poll( ctx->client, &ctx->shred_version, charge_busy );
  if( FD_UNLIKELY( !result ) ) {
    if( FD_UNLIKELY( ctx->expected_shred_version && ctx->expected_shred_version!=ctx->shred_version ) ) {
      FD_LOG_ERR(( "Expected shred version %hu but entrypoint returned %hu",
                   ctx->expected_shred_version, ctx->shred_version ));
    }

    FD_LOG_INFO(( "retrieved shred version %hu from entrypoint", ctx->shred_version ));
    FD_MGAUGE_SET( IPECHO, SHRED_VERSION, ctx->shred_version );
    fd_stem_publish( stem, 0UL, ctx->shred_version, 0UL, 0UL, 0UL, 0UL, 0UL );
    fd_ipecho_server_set_shred_version( ctx->server, ctx->shred_version );
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

static inline int
returnable_frag( fd_ipecho_tile_ctx_t * ctx,
                 ulong                  in_idx,
                 ulong                  seq,
                 ulong                  sig,
                 ulong                  chunk,
                 ulong                  sz,
                 ulong                  ctl,
                 ulong                  tsorig,
                 ulong                  tspub,
                 fd_stem_context_t *    stem ) {
  (void)in_idx;
  (void)seq;
  (void)chunk;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  FD_TEST( sig && sig<=USHORT_MAX );
  ctx->shred_version = (ushort)sig;
  FD_TEST( !ctx->expected_shred_version || ctx->shred_version==ctx->expected_shred_version );
  FD_MGAUGE_SET( IPECHO, SHRED_VERSION, ctx->shred_version );
  fd_stem_publish( stem, 0UL, ctx->shred_version, 0UL, 0UL, 0UL, tsorig, fd_frag_meta_ts_comp( fd_tickcount() ) );
  fd_ipecho_server_set_shred_version( ctx->server, ctx->shred_version );
  ctx->retrieving = 0;

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
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
    ctx->client = NULL;
  }

  ctx->server = fd_ipecho_server_join( fd_ipecho_server_new( _server, 1024UL ) );
  FD_TEST( ctx->server );
  fd_ipecho_server_init( ctx->server, ctx->bind_address, ctx->bind_port, ctx->shred_version );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* stderr, logfile, one for each socket() call for up to 16
     gossip entrypoints (GOSSIP_TILE_ENTRYPOINTS_MAX) for
     fd_ipecho_client, one for fd_ipecho_server, and up to 1024 for the
     server's connections.  */
  return 1UL +                          /* stderr */
         1UL +                          /* logfile */
         tile->ipecho.entrypoints_cnt + /* for the client */
         1UL +                          /* for the server's socket */
         1024UL;                        /* for the server's connections */;
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

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_ipecho_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ipecho_tile_ctx_t), sizeof(fd_ipecho_tile_ctx_t) );

  /* We expect to have at mininum 3 file descriptors open:
     - stderr
     - logfile
     - server socket
     We can't account for any of the file descriptors that were likely
     opened by the ipecho client because it is possible that none of the
     sockets were able to successfully connect. */
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) {
    FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  }

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  /* All of the fds managed by the client. */
  for( ulong i=0UL; i<tile->ipecho.entrypoints_cnt; i++ ) {
    int fd = fd_ipecho_client_get_pollfds( ctx->client )[ i ].fd;
    if( FD_LIKELY( fd!=-1 ) ) out_fds[ out_cnt++ ] = fd;
  }

  /* The server's socket. */
  out_fds[ out_cnt++ ] = fd_ipecho_server_sockfd( ctx->server );
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_ipecho_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_ipecho_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_ipecho = {
  .name                     = "ipecho",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
  .allow_connect            = 1,
  .keep_host_networking     = 1
};
