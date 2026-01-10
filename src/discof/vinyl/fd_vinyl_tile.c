/* The 'vinyl' tile is a thin wrapper over 'fd_vinyl_exec'.

   This tile sleeps (using stem) until the system boots initial chain
   state (from snapshot or genesis).  Then, fd_vinyl_exec hijacks the
   stem run loop and takes over. */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../vinyl/fd_vinyl.h"
#include "../../vinyl/io/fd_vinyl_io_ur.h"
#include "../../util/pod/fd_pod_format.h"

#include <errno.h>
#include <fcntl.h>
#if FD_HAS_LIBURING
#include <liburing.h>
#endif

#define NAME "vinyl"
#define MAX_INS 8
#define MAX_CLIENTS 8

#define IO_SPAD_MAX (32UL<<20)

struct fd_vinyl_tile_ctx {
  fd_vinyl_t * vinyl;
  int          bstream_fd;

  void * io_mem;
  void * vinyl_mem;
  void * line_mem;     ulong line_footprint;
  void * cnc_mem;      ulong cnc_footprint;
  void * meta_mem;     ulong meta_footprint;
  void * ele_mem;      ulong ele_footprint;
  void * obj_mem;      ulong obj_footprint;

  ulong volatile const * snapin_state;

  struct io_uring * ring;
# if FD_HAS_LIBURING
  struct io_uring _ring[1];
# endif

  struct {
    fd_wksp_t *     rq_wksp;
    ulong           rq_gaddr;
    fd_wksp_t *     cq_wksp;
    ulong           cq_gaddr;
    fd_wksp_t *     req_pool_wksp;
    ulong           link_id;
    ulong           burst_max;
    ulong           quota_max;
  } client_param[ MAX_CLIENTS ];
  uint client_active_cnt;
  uint client_cnt;
  uint client_join_inflight : 1;
};

typedef struct fd_vinyl_tile_ctx fd_vinyl_tile_ctx_t;

#if FD_HAS_LIBURING

static struct io_uring_params *
vinyl_io_uring_params( struct io_uring_params * params,
                       uint                     uring_depth ) {
  memset( params, 0, sizeof(struct io_uring_params) );
  params->flags      |= IORING_SETUP_CQSIZE;
  params->cq_entries  = uring_depth;
  params->flags      |= IORING_SETUP_COOP_TASKRUN;
  params->flags      |= IORING_SETUP_SINGLE_ISSUER;
  params->flags      |= IORING_SETUP_R_DISABLED;
  params->features   |= IORING_SETUP_DEFER_TASKRUN;
  return params;
}

#endif


static ulong
scratch_align( void ) {
  return FD_SHMEM_HUGE_PAGE_SZ;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_tile_ctx_t), sizeof(fd_vinyl_tile_ctx_t) );
  if( tile->vinyl.io_type==FD_VINYL_IO_TYPE_UR ) {
#   if FD_HAS_LIBURING
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_ur_align(), fd_vinyl_io_ur_footprint( IO_SPAD_MAX ) );
#   endif
  } else {
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_bd_align(), fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  }
  l = FD_LAYOUT_APPEND( l, fd_vinyl_align(),         fd_vinyl_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_cnc_align(),           fd_cnc_footprint( FD_VINYL_CNC_APP_SZ ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_line_t), sizeof(fd_vinyl_line_t)*tile->vinyl.vinyl_line_max );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* FIXME Pre-register database clients

   Ideally, we'd pre-register all database clients with the server at
   initialization time (since all client data structures are allocated
   upfront).  But the vinyl_exec run loop can only register new
   clients post-initialization.  So, for now housekeep will be
   responsible for registering clients from within. */

static void
register_clients( fd_vinyl_tile_ctx_t * ctx ) {
  fd_cnc_t *       cnc = ctx->vinyl->cnc;
  fd_vinyl_cmd_t * cmd = fd_cnc_app_laddr( cnc );

  int err = fd_cnc_open( cnc );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_cnc_open failed (%i-%s)", err, fd_cnc_strerror( err ) ));

  /* See if the vinyl_cnc is ready to accept new requests */

  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_RUN ) ) {
    fd_cnc_close( cnc );
    return;
  }

  /* See if a previous client join request finished */

  if( ctx->client_join_inflight ) {
    int err = cmd->join.err;
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to initialize vinyl tile (%i-%s)", err, fd_vinyl_strerror( err ) ));
    }

    ulong       client_idx    = ctx->client_active_cnt;
    fd_wksp_t * rq_wksp       = ctx->client_param[ client_idx ].rq_wksp;
    ulong       rq_gaddr      = ctx->client_param[ client_idx ].rq_gaddr;
    fd_wksp_cstr( rq_wksp, rq_gaddr, cmd->join.rq );
    FD_LOG_INFO(( "joined client %u with rq %s:%lu", ctx->client_active_cnt, fd_wksp_name( rq_wksp ), rq_gaddr ));

    ctx->client_active_cnt++;
    ctx->client_join_inflight = 0;

    fd_cnc_close( cnc );
    return;
  }

  /* Join the next client */

  ulong       client_idx    = ctx->client_active_cnt;
  fd_wksp_t * rq_wksp       = ctx->client_param[ client_idx ].rq_wksp;
  ulong       rq_gaddr      = ctx->client_param[ client_idx ].rq_gaddr;
  fd_wksp_t * cq_wksp       = ctx->client_param[ client_idx ].cq_wksp;
  ulong       cq_gaddr      = ctx->client_param[ client_idx ].cq_gaddr;
  fd_wksp_t * req_pool_wksp = ctx->client_param[ client_idx ].req_pool_wksp;

  cmd->join.err       = 0;
  cmd->join.link_id   = ctx->client_param[ client_idx ].link_id;
  cmd->join.burst_max = ctx->client_param[ client_idx ].burst_max;
  cmd->join.quota_max = ctx->client_param[ client_idx ].quota_max;
  fd_cstr_ncpy( cmd->join.wksp, fd_wksp_name( req_pool_wksp ), FD_SHMEM_NAME_MAX );
  fd_wksp_cstr( rq_wksp, rq_gaddr, cmd->join.rq );
  fd_wksp_cstr( cq_wksp, cq_gaddr, cmd->join.cq );

  ctx->client_join_inflight = 1;
  fd_cnc_signal( cnc, FD_VINYL_CNC_SIGNAL_CLIENT_JOIN );
  fd_cnc_close( cnc );
}

/* vinyl_housekeep is periodically called by the vinyl_exec run loop.
   Does async startup tasks and metric publishing. */

static void
vinyl_housekeep( void * ctx_ ) {
  fd_vinyl_tile_ctx_t * ctx = ctx_;

  long now = fd_tickcount();
  FD_MGAUGE_SET( TILE, HEARTBEAT, (ulong)now );

  if( FD_UNLIKELY( ctx->client_active_cnt < ctx->client_cnt ) ) {
    register_clients( ctx );
    if( ctx->client_active_cnt==ctx->client_cnt ) {
      FD_LOG_INFO(( "Vinyl tile initialization complete" ));
    }
  }
}

/* vinyl_init_fast is a variation of fd_vinyl_init.  Creates tile
   private data structures and formats shared cache objects.  Reuses
   existing io/bstream/meta. */

static void
vinyl_init_fast( fd_vinyl_tile_ctx_t * ctx,
                 void * _vinyl,
                 void * _cnc,  ulong cnc_footprint,
                 void * _meta, ulong meta_footprint,
                 void * _line, ulong line_footprint,
                 void * _ele,  ulong ele_footprint,
                 void * _obj,  ulong obj_footprint,
                 fd_vinyl_io_t * io,
                 void *          obj_laddr0,
                 ulong           async_min,
                 ulong           async_max,
                 ulong           part_thresh,
                 ulong           gc_thresh,
                 int             gc_eager ) {
  ulong ele_max  = fd_ulong_pow2_dn( ele_footprint / sizeof( fd_vinyl_meta_ele_t ) );
  ulong pair_max = ele_max - 1UL;
  ulong line_cnt = fd_ulong_min( line_footprint / sizeof( fd_vinyl_line_t ), pair_max );

  FD_TEST( (3UL<=line_cnt) & (line_cnt<=FD_VINYL_LINE_MAX) );
  FD_TEST( io );
  FD_TEST( (0UL<async_min) & (async_min<=async_max) );
  FD_TEST( (-1<=gc_eager) & (gc_eager<=63) );

  fd_vinyl_t * vinyl = (fd_vinyl_t *)_vinyl;
  memset( vinyl, 0, fd_vinyl_footprint() );

  vinyl->cnc = fd_cnc_join( fd_cnc_new( _cnc, FD_VINYL_CNC_APP_SZ, FD_VINYL_CNC_TYPE, fd_log_wallclock() ) );
  FD_TEST( vinyl->cnc );
  vinyl->line = (fd_vinyl_line_t *)_line;
  vinyl->io   = io;

  vinyl->line_cnt  = line_cnt;
  vinyl->pair_max  = pair_max;
  vinyl->async_min = async_min;
  vinyl->async_max = async_max;

  vinyl->part_thresh  = part_thresh;
  vinyl->gc_thresh    = gc_thresh;
  vinyl->gc_eager     = gc_eager;
  vinyl->style        = FD_VINYL_BSTREAM_CTL_STYLE_RAW;
  vinyl->line_idx_lru = 0U;
  vinyl->pair_cnt     = 0UL;
  vinyl->garbage_sz   = 0UL;

  FD_TEST( fd_vinyl_meta_join( vinyl->meta, _meta, _ele ) );

  FD_TEST( fd_vinyl_data_init( vinyl->data, _obj, obj_footprint, obj_laddr0 ) );
  fd_vinyl_data_reset( NULL, 0UL, 0UL, 0, vinyl->data );

  vinyl->cnc_footprint  = cnc_footprint;
  vinyl->meta_footprint = meta_footprint;
  vinyl->line_footprint = line_footprint;
  vinyl->ele_footprint  = ele_footprint;
  vinyl->obj_footprint  = obj_footprint;

  ctx->vinyl = vinyl;

  FD_LOG_NOTICE(( "Vinyl config"
                  "\n\tline_cnt    %lu pairs"
                  "\n\tpair_max    %lu pairs"
                  "\n\tasync_min   %lu min iterations per async"
                  "\n\tasync_max   %lu max iterations per async"
                  "\n\tpart_thresh %lu bytes"
                  "\n\tgc_thresh   %lu bytes"
                  "\n\tgc_eager    %i",
                  line_cnt, pair_max, async_min, async_max, part_thresh, gc_thresh, gc_eager ));
}

#if FD_HAS_LIBURING

static void
vinyl_io_uring_init( fd_vinyl_tile_ctx_t * ctx,
                     uint                  uring_depth,
                     int                   dev_fd ) {
  ctx->ring = ctx->_ring;

  /* Setup io_uring instance */
  struct io_uring_params params[1];
  vinyl_io_uring_params( params, uring_depth );
  int init_err = io_uring_queue_init_params( uring_depth, ctx->ring, params );
  if( FD_UNLIKELY( init_err<0 ) ) FD_LOG_ERR(( "io_uring_queue_init_params failed (%i-%s)", init_err, fd_io_strerror( -init_err ) ));

  /* Setup io_uring file access */
  FD_TEST( 0==io_uring_register_files( ctx->ring, &dev_fd, 1 ) );

  /* Register restrictions */
  struct io_uring_restriction res[3] = {
    { .opcode    = IORING_RESTRICTION_SQE_OP,
      .sqe_op    = IORING_OP_READ },
    { .opcode    = IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
      .sqe_flags = IOSQE_FIXED_FILE },
    { .opcode    = IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
      .sqe_flags = IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS }
  };
  int res_err = io_uring_register_restrictions( ctx->ring, res, 3U );
  if( FD_UNLIKELY( res_err<0 ) ) FD_LOG_ERR(( "io_uring_register_restrictions failed (%i-%s)", res_err, fd_io_strerror( -res_err ) ));

  /* Enable rings */
  int enable_err = io_uring_enable_rings( ctx->ring );
  if( FD_UNLIKELY( enable_err<0 ) ) FD_LOG_ERR(( "io_uring_enable_rings failed (%i-%s)", enable_err, fd_io_strerror( -enable_err ) ));
}

#else /* no io_uring */

static void
vinyl_io_uring_init( fd_vinyl_tile_ctx_t * ctx,
                     uint                  uring_depth,
                     int                   dev_fd ) {
  (void)ctx; (void)uring_depth; (void)dev_fd;
  FD_LOG_ERR(( "Sorry, this build does not support io_uring" ));
}

#endif

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  ulong cnc_footprint = fd_cnc_footprint( FD_VINYL_CNC_APP_SZ );
  ulong line_footprint;
  if( FD_UNLIKELY( !tile->vinyl.vinyl_line_max || __builtin_umull_overflow( tile->vinyl.vinyl_line_max, sizeof(fd_vinyl_line_t), &line_footprint ) ) ) {
    FD_LOG_ERR(( "invalid vinyl_line_max %lu", tile->vinyl.vinyl_line_max ));
  }

  void * tile_mem = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, tile_mem );
  fd_vinyl_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_tile_ctx_t), sizeof(fd_vinyl_tile_ctx_t) );
  void * _io = NULL;
  if( tile->vinyl.io_type==FD_VINYL_IO_TYPE_UR ) {
#   if FD_HAS_LIBURING
    _io = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_ur_align(), fd_vinyl_io_ur_footprint( IO_SPAD_MAX ) );
#   endif
  } else {
    _io = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_bd_align(), fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  }
  void *            vinyl_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_align(), fd_vinyl_footprint()   );
  void *            _cnc      = FD_SCRATCH_ALLOC_APPEND( l, fd_cnc_align(),   cnc_footprint          );
  fd_vinyl_line_t * _line     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_line_t), line_footprint );
  ulong             _end      = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( (ulong)tile_mem==(ulong)ctx );
  FD_TEST( (ulong)_end-(ulong)tile_mem==scratch_footprint( tile ) );

  memset( ctx, 0, sizeof(fd_vinyl_tile_ctx_t) );

  void * _meta = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_meta_map_obj_id  );
  void * _ele  = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_meta_pool_obj_id );
  void * _obj  = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_data_obj_id      );

  ctx->io_mem    = _io;
  ctx->vinyl_mem = vinyl_mem;
  ctx->cnc_mem   = _cnc;   ctx->cnc_footprint  = cnc_footprint;
  ctx->meta_mem  = _meta;  ctx->meta_footprint = topo->objs[ tile->vinyl.vinyl_meta_map_obj_id  ].footprint;
  ctx->line_mem  = _line;  ctx->line_footprint = line_footprint;
  ctx->ele_mem   = _ele;   ctx->ele_footprint  = topo->objs[ tile->vinyl.vinyl_meta_pool_obj_id ].footprint;
  ctx->obj_mem   = _obj;   ctx->obj_footprint  = topo->objs[ tile->vinyl.vinyl_data_obj_id      ].footprint;

  /* FIXME use O_DIRECT? */
  int dev_fd = open( tile->vinyl.vinyl_bstream_path, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( dev_fd<0 ) ) FD_LOG_ERR(( "open(%s,O_RDWR|O_CLOEXEC) failed (%i-%s)", tile->vinyl.vinyl_bstream_path, errno, fd_io_strerror( errno ) ));

  ctx->bstream_fd = dev_fd;

  int io_type = tile->vinyl.io_type;
  if( io_type==FD_VINYL_IO_TYPE_UR ) {
    vinyl_io_uring_init( ctx, tile->vinyl.uring_depth, dev_fd );
  } else if( io_type!=FD_VINYL_IO_TYPE_BD ) {
    FD_LOG_ERR(( "Unsupported vinyl io_type %d", io_type ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  fd_vinyl_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /* Find snapin tile status */
  ulong snapin_tile_idx = fd_topo_find_tile( topo, "snapin", 0UL );
  FD_TEST( snapin_tile_idx!=ULONG_MAX );
  fd_topo_tile_t const * snapin_tile = &topo->tiles[ snapin_tile_idx ];
  FD_TEST( snapin_tile->metrics );
  ctx->snapin_state = &fd_metrics_tile( snapin_tile->metrics )[ MIDX( GAUGE, TILE, STATUS ) ];

  /* Join a public CNC if provided (development only) */
  if( tile->vinyl.vinyl_cnc_obj_id!=ULONG_MAX ) {
    ctx->cnc_mem       = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_cnc_obj_id );
    ctx->cnc_footprint = topo->objs[ tile->vinyl.vinyl_cnc_obj_id ].footprint;
  }

  /* Discover mapped clients */
  for( ulong i=0UL; i<(tile->uses_obj_cnt); i++ ) {
    ulong rq_obj_id = tile->uses_obj_id[ i ];
    fd_topo_obj_t const * rq_obj = &topo->objs[ rq_obj_id ];
    if( strcmp( rq_obj->name, "vinyl_rq" ) ) continue;
    FD_TEST( ctx->client_cnt<MAX_CLIENTS );

    ulong link_id         = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.link_id",         rq_obj_id );
    ulong quota_max       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.quota_max",       rq_obj_id );
    ulong req_pool_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.req_pool_obj_id", rq_obj_id );
    ulong cq_obj_id       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.cq_obj_id",       rq_obj_id );
    FD_TEST( link_id        !=ULONG_MAX );
    FD_TEST( quota_max      !=ULONG_MAX );
    FD_TEST( req_pool_obj_id!=ULONG_MAX );
    FD_TEST( cq_obj_id      !=ULONG_MAX );
    fd_topo_obj_t const * cq_obj       = &topo->objs[ cq_obj_id       ];
    fd_topo_obj_t const * req_pool_obj = &topo->objs[ req_pool_obj_id ];

    ulong client_idx = ctx->client_cnt++;
    ctx->client_param[ client_idx ].rq_wksp       = topo->workspaces[ rq_obj->wksp_id ].wksp;
    ctx->client_param[ client_idx ].rq_gaddr      = rq_obj->offset;
    ctx->client_param[ client_idx ].cq_wksp       = topo->workspaces[ cq_obj->wksp_id ].wksp;
    ctx->client_param[ client_idx ].cq_gaddr      = cq_obj->offset;
    ctx->client_param[ client_idx ].req_pool_wksp = topo->workspaces[ req_pool_obj->wksp_id ].wksp;
    ctx->client_param[ client_idx ].link_id       = link_id;
    ctx->client_param[ client_idx ].burst_max     = 1UL;
    ctx->client_param[ client_idx ].quota_max     = quota_max;
  }
}

__attribute__((noreturn)) static void
enter_vinyl_exec( fd_vinyl_tile_ctx_t * ctx ) {

  fd_vinyl_io_t * io = NULL;
  if( ctx->ring ) {
    io = fd_vinyl_io_ur_init( ctx->io_mem, IO_SPAD_MAX, ctx->bstream_fd, ctx->ring );
    if( FD_UNLIKELY( !io ) ) FD_LOG_ERR(( "Failed to initialize io_uring I/O backend for account database" ));
  } else {
    io = fd_vinyl_io_bd_init( ctx->io_mem, IO_SPAD_MAX, ctx->bstream_fd, 0, NULL, 0UL, 0UL );
    if( FD_UNLIKELY( !io ) ) FD_LOG_ERR(( "Failed to initialize blocking I/O backend for account database" ));
  }

  ulong async_min   =         5UL;
  ulong async_max   = 2*async_min;
  ulong part_thresh =    64UL<<20;
  ulong gc_thresh   =   128UL<<20;
  int   gc_eager    =           2;

  vinyl_init_fast(
      ctx,
      ctx->vinyl_mem,
      ctx->cnc_mem,  ctx->cnc_footprint,
      ctx->meta_mem, ctx->meta_footprint,
      ctx->line_mem, ctx->line_footprint,
      ctx->ele_mem,  ctx->ele_footprint,
      ctx->obj_mem,  ctx->obj_footprint,
      io,
      fd_wksp_containing( ctx->obj_mem ),
      async_min, async_max,
      part_thresh,
      gc_thresh,
      gc_eager );
  ctx->vinyl->housekeep     = vinyl_housekeep;
  ctx->vinyl->housekeep_ctx = ctx;

  fd_vinyl_line_t * line     = ctx->vinyl->line;
  ulong const       line_cnt = ctx->vinyl->line_cnt;
  for( ulong line_idx=0UL; line_idx<line_cnt; line_idx++ ) {
    line[ line_idx ].obj            = NULL;
    line[ line_idx ].ele_idx        = ULONG_MAX;
    line[ line_idx ].ctl            = fd_vinyl_line_ctl( 0UL, 0L);
    line[ line_idx ].line_idx_older = (uint)fd_ulong_if( line_idx!=0UL,          line_idx-1UL, line_cnt-1UL );
    line[ line_idx ].line_idx_newer = (uint)fd_ulong_if( line_idx!=line_cnt-1UL, line_idx+1UL, 0UL          );
  }

  fd_vinyl_exec( ctx->vinyl );
  FD_LOG_CRIT(( "Vinyl tile stopped unexpectedly" ));
}

static void
during_housekeeping( fd_vinyl_tile_ctx_t * ctx ) {

  ulong const snapin_state = FD_VOLATILE_CONST( *ctx->snapin_state );
  if( snapin_state==2UL ) {
    /* Once snapin tile exits, boot up vinyl */
    FD_LOG_INFO(( "booting up vinyl tile" ));
    enter_vinyl_exec( ctx );
    FD_LOG_CRIT(( "vinyl tile crashed" ));
  }

  fd_log_sleep( 1e6 ); /* 1 ms */

}

#define STEM_BURST (1UL)
#define STEM_LAZY (100000UL)
#define STEM_CALLBACK_CONTEXT_TYPE        fd_vinyl_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN       fd_vinyl_align()
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_vinyl = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};

#undef NAME
