#include "../../fdctl/run/tiles/tiles.h"

#include <linux/unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  ulong round_robin_cnt;
  ulong round_robin_id;

  ulong packet_cnt;

  ulong conn_cnt;
  int conn_fd[ 128UL ];

  fd_wksp_t * mem;
} fd_benchs_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_benchs_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_benchs_ctx_t ) );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)sig;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  if( FD_UNLIKELY( (seq%ctx->round_robin_cnt)!=ctx->round_robin_id ) ) {
    *opt_filter = 1;
    return;
  }
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  if( FD_UNLIKELY( -1==send( ctx->conn_fd[ ctx->packet_cnt % ctx->conn_cnt ], fd_chunk_to_laddr( ctx->mem, chunk ), sz, 0 ) ) )
    FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->packet_cnt++;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  ushort port = 12000;

  ctx->conn_cnt = tile->benchs.conn_cnt;
  FD_TEST( ctx->conn_cnt <=sizeof(ctx->conn_fd)/sizeof(*ctx->conn_fd) );
  for( ulong i=0UL; i<ctx->conn_cnt ; i++ ) {
    int conn_fd = socket( AF_INET, SOCK_DGRAM, 0 );
    if( FD_UNLIKELY( -1==conn_fd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ushort found_port = 0;
    for( ulong j=0UL; j<10UL; j++ ) {
      struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = fd_ushort_bswap( port ),
        .sin_addr.s_addr = fd_uint_bswap( INADDR_ANY ),
      };
      if( FD_UNLIKELY( -1!=bind( conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
        found_port = port;
        break;
      }
      if( FD_UNLIKELY( EADDRINUSE!=errno ) ) FD_LOG_ERR(( "bind() failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
      port = (ushort)(port + ctx->conn_cnt); /* Make sure it round robins to the same tile index */
    }
    if( FD_UNLIKELY( !found_port ) ) FD_LOG_ERR(( "bind() failed to find a src port" ));

    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = fd_ushort_bswap( tile->benchs.send_to_port ),
      .sin_addr.s_addr = tile->benchs.send_to_ip_addr,
    };
    if( FD_UNLIKELY( -1==connect( conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ctx->conn_fd[ i ] = conn_fd;
    port++;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  ctx->packet_cnt = 0UL;

  ctx->round_robin_id = tile->kind_id;
  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, "benchs" );

  ctx->mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

fd_topo_run_tile_t fd_tile_benchs = {
  .name                     = "benchs",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
