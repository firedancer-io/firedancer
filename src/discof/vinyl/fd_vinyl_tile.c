/* The 'vinyl' tile is a thin wrapper over 'fd_vinyl_exec'.

   This tile sleeps (using stem) until the system boots initial chain
   state (from snapshot or genesis).  Then, fd_vinyl_exec hijacks the
   stem run loop and takes over. */

#include "../../disco/topo/fd_topo.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../vinyl/fd_vinyl.h"

#include <errno.h>
#include <fcntl.h>

#define NAME "vinyl"
#define MAX_INS 8

#define IN_KIND_GENESIS 1
#define IN_KIND_SNAP    2

#define IO_SPAD_MAX (32UL<<20)

struct fd_vinyl_tile_ctx {
  fd_vinyl_t * vinyl;
  uint         in_kind[ MAX_INS ];
  int          bstream_fd;

  void * io_mem;
  void * vinyl_mem;
  void * line_mem;     ulong line_footprint;
  void * cnc_mem;      ulong cnc_footprint;
  void * meta_mem;     ulong meta_footprint;
  void * ele_mem;      ulong ele_footprint;
  void * obj_mem;      ulong obj_footprint;

  ulong * snapin_manif_fseq;
};

typedef struct fd_vinyl_tile_ctx fd_vinyl_tile_ctx_t;

static ulong
scratch_align( void ) {
  return fd_vinyl_align();
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_tile_ctx_t), sizeof(fd_vinyl_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_align(),         fd_vinyl_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_cnc_align(),           fd_cnc_footprint( FD_VINYL_CNC_APP_SZ ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_line_t), sizeof(fd_vinyl_line_t)*tile->vinyl.vinyl_line_max );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_io_bd_align(),   fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* vinyl_init_io creates a vinyl_io object over an existing bstream
   file. */

static fd_vinyl_io_t *
vinyl_init_io( void * _io,
               ulong  spad_max,
               int    dev_fd ) {
  fd_vinyl_io_t * io = fd_vinyl_io_bd_init( _io, spad_max, dev_fd, 0, NULL, 0UL, 0UL );
  if( FD_UNLIKELY( !io ) ) FD_LOG_ERR(( "Failed to initialize I/O backend for account database" ));
  return io;
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

  vinyl->cnc_footprint  = cnc_footprint;
  vinyl->meta_footprint = meta_footprint;
  vinyl->line_footprint = line_footprint;
  vinyl->ele_footprint  = ele_footprint;
  vinyl->obj_footprint  = obj_footprint;

  ctx->vinyl = vinyl;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo;
  fd_vinyl_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_vinyl_tile_ctx_t) );

  /* FIXME use O_DIRECT? */
  int dev_fd = open( tile->vinyl.vinyl_bstream_path, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( dev_fd<0 ) ) FD_LOG_ERR(( "open(%s,O_RDWR|O_CLOEXEC) failed (%i-%s)", tile->vinyl.vinyl_bstream_path, errno, fd_io_strerror( errno ) ));

  ctx->bstream_fd = dev_fd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  ulong cnc_footprint = fd_cnc_footprint( FD_VINYL_CNC_APP_SZ );
  ulong line_footprint;
  if( FD_UNLIKELY( !tile->vinyl.vinyl_line_max || __builtin_umull_overflow( tile->vinyl.vinyl_line_max, sizeof(fd_vinyl_line_t), &line_footprint ) ) ) {
    FD_LOG_ERR(( "invalid vinyl_line_max %lu", tile->vinyl.vinyl_line_max ));
  }

  void * tile_mem = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, tile_mem );
  fd_vinyl_tile_ctx_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_tile_ctx_t), sizeof(fd_vinyl_tile_ctx_t) );
  void *                vinyl_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_align(), fd_vinyl_footprint()   );
  void *                _cnc      = FD_SCRATCH_ALLOC_APPEND( l, fd_cnc_align(),   cnc_footprint          );
  fd_vinyl_line_t *     _line     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_line_t), line_footprint );
  void *                _io       = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_bd_align(), fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( (ulong)tile_mem==(ulong)ctx );

  ulong manif_in_idx = fd_topo_find_tile_in_link( topo, tile, "snapin_manif", 0UL );
  FD_TEST( manif_in_idx!=ULONG_MAX );
  FD_TEST( manif_in_idx<MAX_INS );
  ctx->in_kind[ manif_in_idx ] = IN_KIND_SNAP;

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

  /* Join a public CNC if provided (development only) */
  if( tile->vinyl.vinyl_cnc_obj_id!=ULONG_MAX ) {
    ctx->cnc_mem       = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_cnc_obj_id );
    ctx->cnc_footprint = topo->objs[ tile->vinyl.vinyl_cnc_obj_id ].footprint;
  }

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0 ] ];
  FD_TEST( in_link && 0==strcmp( in_link->name, "snapin_manif" ) );
  if( FD_UNLIKELY( !tile->in_link_reliable[ 0 ] ) ) FD_LOG_ERR(( "tile `" NAME "` in link 0 must be reliable" ));
  ctx->snapin_manif_fseq = tile->in_link_fseq[ 0 ];
}

__attribute__((noreturn)) static void
enter_vinyl_exec( fd_vinyl_tile_ctx_t * ctx ) {

  fd_vinyl_io_t * io = vinyl_init_io( ctx->io_mem, IO_SPAD_MAX, ctx->bstream_fd );
  FD_TEST( io );

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

  fd_vinyl_exec( ctx->vinyl );
  FD_LOG_CRIT(( "Vinyl tile stopped unexpectedly" ));
}

static void
on_genesis_ctrl( fd_vinyl_tile_ctx_t * ctx,
                 ulong                 sig ) {
  (void)ctx; (void)sig;
  FD_LOG_ERR(( "Sorry, booting off vinyl is not yet supported" ));
}

static void
on_snap_ctrl( fd_vinyl_tile_ctx_t * ctx,
              ulong                 sig ) {
  ulong msg_type = fd_ssmsg_sig_message( sig );
  if( msg_type==FD_SSMSG_DONE ) {
    FD_LOG_INFO(( "Vinyl tile booting" ));
    fd_fseq_update( ctx->snapin_manif_fseq, ULONG_MAX-1UL ); /* mark consumer as shut down */
    enter_vinyl_exec( ctx );
  }
}

static inline void
during_frag( fd_vinyl_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz     FD_PARAM_UNUSED,
             ulong                 ctl    FD_PARAM_UNUSED ) {
  (void)seq; (void)chunk;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_GENESIS:
    on_genesis_ctrl( ctx, sig );
    break;
  case IN_KIND_SNAP:
    on_snap_ctrl( ctx, sig );
    break;
  default:
    FD_LOG_CRIT(( "Frag from unexpected in_idx %lu", in_idx ));
  }
}

#define STEM_BURST (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_vinyl_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN fd_vinyl_align()
#define STEM_CALLBACK_DURING_FRAG   during_frag

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
