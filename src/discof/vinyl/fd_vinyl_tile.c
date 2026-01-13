/* Vinyl database server (Firedancer adaptation)

   This implementation is a fork of src/vinyl/fd_vinyl_exec with some
   Firedancer-specific changes:
   - All clients are joined on startup
   - Some errors (invalid link_id, invalid comp_gaddr) result in hard
     crashes instead of silent drops
   - Sandboxing */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../vinyl/fd_vinyl.h"
#include "../../vinyl/fd_vinyl_base.h"
#include "../../vinyl/io/fd_vinyl_io_ur.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/trace/generated/fd_trace_db_server.h"

#include <errno.h>
#include <fcntl.h>
#include <lz4.h>
#if FD_HAS_LIBURING
#include <liburing.h>
#endif

#define NAME "vinyl"
#define MAX_INS 8

#define IO_SPAD_MAX (32UL<<20)

#define FD_VINYL_CLIENT_MAX (32UL)
#define FD_VINYL_REQ_MAX (1024UL)

struct fd_vinyl_client {
  fd_vinyl_rq_t * rq;        /* Channel for requests from this client (could be shared by multiple vinyl instances) */
  fd_vinyl_cq_t * cq;        /* Channel for completions from this client to this vinyl instance
                                (could be shared by multiple receivers of completions from this vinyl instance). */
  ulong           burst_max; /* Max requests receive from this client at a time */
  ulong           seq;       /* Sequence number of the next request to receive in the rq */
  ulong           link_id;   /* Identifies requests from this client to this vinyl instance in the rq */
  ulong           laddr0;    /* A valid non-zero gaddr from this client maps to the vinyl instance's laddr laddr0 + gaddr ... */
  ulong           laddr1;    /* ... and thus is in (laddr0,laddr1).  A zero gaddr maps to laddr NULL. */
  ulong           quota_rem; /* Num of remaining acquisitions this client is allowed on this vinyl instance */
  ulong           quota_max; /* Max quota */
};

typedef struct fd_vinyl_client fd_vinyl_client_t;

/* MAP_REQ_GADDR maps a request global address req_gaddr to an array of
   cnt T's into the local address space as a T * pointer.  If the result
   is not properly aligned or the entire range does not completely fall
   within the shared region with the client, returns NULL.  Likewise,
   gaadr 0 maps to NULL.  Assumes sizeof(T)*(n) does not overflow (which
   is true where as n is at most batch_cnt which is at most 2^32 and
   sizeof(T) is at most 40. */

#define MAP_REQ_GADDR( gaddr, T, n ) ((T *)fd_vinyl_laddr( (gaddr), alignof(T), sizeof(T)*(n), client_laddr0, client_laddr1 ))

FD_FN_CONST static inline void *
fd_vinyl_laddr( ulong req_gaddr,
                ulong align,
                ulong footprint,
                ulong client_laddr0,
                ulong client_laddr1 ) {
  ulong req_laddr0 = client_laddr0 + req_gaddr;
  ulong req_laddr1 = req_laddr0    + footprint;
  return (void *)fd_ulong_if( (!!req_gaddr) & fd_ulong_is_aligned( req_laddr0, align ) &
                              (client_laddr0<=req_laddr0) & (req_laddr0<=req_laddr1) & (req_laddr1<=client_laddr1),
                              req_laddr0, 0UL );
}

struct fd_vinyl_tile {

  /* Vinyl objects */

  fd_vinyl_t vinyl[1];
  void * io_mem;

  /* Tile architecture */

  uint booted : 1;
  uint shutdown : 1;
  ulong volatile const * snapin_state;

  /* I/O */

  int               bstream_fd;
  struct io_uring * ring;

  /* Clients */

  fd_vinyl_client_t _client[ FD_VINYL_CLIENT_MAX ];
  ulong             client_cnt;
  ulong             client_idx;

  /* Received requests */

  fd_vinyl_req_t _req[ FD_VINYL_REQ_MAX ];
  ulong          req_head;                 /* Requests [0,req_head)         have been processed */
  ulong          req_tail;                 /* Requests [req_head,req_tail)  are pending */
                                           /* Requests [req_tail,ULONG_MAX) have not been received */
  ulong exec_max;

  /* accum_dead_cnt is the number of dead blocks that have been
     written since the last partition block.

     accum_move_cnt is the number of move blocks that have been
     written since this last partition block.

     accum_garbage_cnt / sz is the number of items / bytes garbage in
     the bstream that have accumulated since the last time we compacted
     the bstream.  We use this to estimate the number of rounds of
     compaction to do in async handling. */

  ulong accum_dead_cnt;
  ulong accum_garbage_cnt;
  ulong accum_garbage_sz;

  /* Run loop state */

  ulong seq_part;

  /* Place optional/external data structures last so the above struct
     offsets are reasonably stable across builds */
# if FD_HAS_LIBURING
  struct io_uring _ring[1];
# endif

};

typedef struct fd_vinyl_tile fd_vinyl_tile_t;

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

/* Vinyl state object */

static ulong
scratch_align( void ) {
  return FD_SHMEM_HUGE_PAGE_SZ;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_tile_t), sizeof(fd_vinyl_tile_t) );
  if( tile->vinyl.io_type==FD_VINYL_IO_TYPE_UR ) {
#   if FD_HAS_LIBURING
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_ur_align(), fd_vinyl_io_ur_footprint( IO_SPAD_MAX ) );
#   endif
  } else {
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_bd_align(), fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  }
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_line_t), sizeof(fd_vinyl_line_t)*tile->vinyl.vinyl_line_max );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

#if FD_HAS_LIBURING

static void
vinyl_io_uring_init( fd_vinyl_tile_t * ctx,
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
vinyl_io_uring_init( fd_vinyl_tile_t * ctx,
                     uint                  uring_depth,
                     int                   dev_fd ) {
  (void)ctx; (void)uring_depth; (void)dev_fd;
  FD_LOG_ERR(( "Sorry, this build does not support io_uring" ));
}

#endif

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  ulong line_footprint;
  if( FD_UNLIKELY( !tile->vinyl.vinyl_line_max || __builtin_umull_overflow( tile->vinyl.vinyl_line_max, sizeof(fd_vinyl_line_t), &line_footprint ) ) ) {
    FD_LOG_ERR(( "invalid vinyl_line_max %lu", tile->vinyl.vinyl_line_max ));
  }

  void * tile_mem = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, tile_mem );
  fd_vinyl_tile_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_tile_t), sizeof(fd_vinyl_tile_t) );
  fd_vinyl_t *      vinyl = ctx->vinyl;
  void * _io = NULL;
  if( tile->vinyl.io_type==FD_VINYL_IO_TYPE_UR ) {
#   if FD_HAS_LIBURING
    _io = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_ur_align(), fd_vinyl_io_ur_footprint( IO_SPAD_MAX ) );
#   endif
  } else {
    _io = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_bd_align(), fd_vinyl_io_bd_footprint( IO_SPAD_MAX ) );
  }
  fd_vinyl_line_t * _line = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_line_t), line_footprint );
  ulong             _end  = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( (ulong)tile_mem==(ulong)ctx );
  FD_TEST( (ulong)_end-(ulong)tile_mem==scratch_footprint( tile ) );

  memset( ctx, 0, sizeof(fd_vinyl_tile_t) );

  ctx->io_mem = _io;

  vinyl->cnc            = NULL;
  vinyl->io             = NULL;
  vinyl->line           = (fd_vinyl_line_t *)_line;
  vinyl->line_footprint = line_footprint;

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

  fd_vinyl_tile_t * ctx   = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_vinyl_t *      vinyl = ctx->vinyl;


  void * _meta = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_meta_map_obj_id  );
  void * _ele  = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_meta_pool_obj_id );
  void * _obj  = fd_topo_obj_laddr( topo, tile->vinyl.vinyl_data_obj_id      );

# define TEST( c ) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_ERR(( "FAIL: %s", #c )); } } while(0)

  vinyl->cnc_footprint  = 0UL;
  vinyl->meta_footprint = topo->objs[ tile->vinyl.vinyl_meta_map_obj_id  ].footprint;
  vinyl->ele_footprint  = topo->objs[ tile->vinyl.vinyl_meta_pool_obj_id ].footprint;
  vinyl->obj_footprint  = topo->objs[ tile->vinyl.vinyl_data_obj_id      ].footprint;

  void * obj_laddr0 = fd_wksp_containing( _obj );
  ulong part_thresh =    64UL<<20;
  ulong gc_thresh   =   128UL<<20;
  int   gc_eager    =           2;

  ulong ele_max  = fd_ulong_pow2_dn( vinyl->ele_footprint / sizeof( fd_vinyl_meta_ele_t ) );

  ulong pair_max = ele_max - 1UL;
  ulong line_cnt = fd_ulong_min( vinyl->line_footprint / sizeof( fd_vinyl_line_t ), pair_max );

  TEST( (3UL<=line_cnt) & (line_cnt<=FD_VINYL_LINE_MAX) );

  /* seed is arb */

  /* part_thresh is arb */

  /* gc_thresh is arb */

  TEST( (-1<=gc_eager) & (gc_eager<=63) );

  vinyl->line_cnt = line_cnt;
  vinyl->pair_max = pair_max;

  vinyl->part_thresh  = part_thresh;
  vinyl->gc_thresh    = gc_thresh;
  vinyl->gc_eager     = gc_eager;
  vinyl->style        = FD_VINYL_BSTREAM_CTL_STYLE_RAW;
  vinyl->line_idx_lru = 0U;
  vinyl->pair_cnt     = 0UL;
  vinyl->garbage_sz   = 0UL;

  TEST( fd_vinyl_meta_join( vinyl->meta, _meta, _ele )==vinyl->meta );

  TEST( fd_vinyl_data_init( vinyl->data, _obj, vinyl->obj_footprint, obj_laddr0 )==vinyl->data );
  fd_vinyl_data_reset( NULL, 0UL, 0UL, 0, vinyl->data );

  fd_vinyl_line_t * line = vinyl->line;
  for( ulong line_idx=0UL; line_idx<line_cnt; line_idx++ ) {
    line[ line_idx ].obj            = NULL;
    line[ line_idx ].ele_idx        = ULONG_MAX;
    line[ line_idx ].ctl            = fd_vinyl_line_ctl( 0UL, 0L);
    line[ line_idx ].line_idx_older = (uint)fd_ulong_if( line_idx!=0UL,          line_idx-1UL, line_cnt-1UL );
    line[ line_idx ].line_idx_newer = (uint)fd_ulong_if( line_idx!=line_cnt-1UL, line_idx+1UL, 0UL          );
  }

# undef TEST

  /* Find snapin tile status */
  ulong snapin_tile_idx = fd_topo_find_tile( topo, "snapin", 0UL );
  FD_TEST( snapin_tile_idx!=ULONG_MAX );
  fd_topo_tile_t const * snapin_tile = &topo->tiles[ snapin_tile_idx ];
  FD_TEST( snapin_tile->metrics );
  ctx->snapin_state = &fd_metrics_tile( snapin_tile->metrics )[ MIDX( GAUGE, TILE, STATUS ) ];

  /* Discover mapped clients */

  ulong burst_free = FD_VINYL_REQ_MAX;
  ulong quota_free = vinyl->line_cnt - 1UL;
  ctx->exec_max = 0UL;

  for( ulong i=0UL; i<(tile->uses_obj_cnt); i++ ) {

    ulong rq_obj_id = tile->uses_obj_id[ i ];
    fd_topo_obj_t const * rq_obj = &topo->objs[ rq_obj_id ];
    if( strcmp( rq_obj->name, "vinyl_rq" ) ) continue;

    if( FD_UNLIKELY( ctx->client_cnt>=FD_VINYL_CLIENT_MAX ) ) {
      FD_LOG_ERR(( "too many vinyl clients (increase FD_VINYL_CLIENT_MAX)" ));
    }

    ulong burst_max       = 1UL;
    ulong link_id         = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.link_id",         rq_obj_id );
    ulong quota_max       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.quota_max",       rq_obj_id );
    ulong req_pool_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.req_pool_obj_id", rq_obj_id );
    ulong cq_obj_id       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.cq_obj_id",       rq_obj_id );
    FD_TEST( link_id        !=ULONG_MAX );
    FD_TEST( quota_max      !=ULONG_MAX );
    FD_TEST( req_pool_obj_id!=ULONG_MAX );
    FD_TEST( cq_obj_id      !=ULONG_MAX );

    if( FD_UNLIKELY( burst_max > burst_free ) ) {
      FD_LOG_ERR(( "too large burst_max (increase FD_VINYL_REQ_MAX or decrease burst_max)" ));
    }

    if( FD_UNLIKELY( quota_max > fd_ulong_min( quota_free, FD_VINYL_COMP_QUOTA_MAX ) ) ) {
      FD_LOG_ERR(( "too large quota_max (increase line_cnt or decrease quota_max)" ));
    }

    for( ulong client_idx=0UL; client_idx<ctx->client_cnt; client_idx++ ) {
      if( FD_UNLIKELY( ctx->_client[ client_idx ].link_id==link_id ) ) {
        FD_LOG_ERR(( "client already joined with this link_id (%lu)", link_id ));
      }
    }

    fd_topo_obj_t const *  req_pool_obj = &topo->objs[ req_pool_obj_id ];
    fd_topo_wksp_t const * client_wksp  = &topo->workspaces[ req_pool_obj->wksp_id ];

    fd_vinyl_rq_t * rq; FD_TEST( (rq = fd_vinyl_rq_join( fd_topo_obj_laddr( topo, rq_obj_id ) )) );
    fd_vinyl_cq_t * cq; FD_TEST( (cq = fd_vinyl_cq_join( fd_topo_obj_laddr( topo, cq_obj_id ) )) );

    fd_shmem_join_info_t join_info;
    FD_TEST( fd_shmem_join_query_by_join( client_wksp->wksp, &join_info)==0 );
    ctx->_client[ ctx->client_cnt ] = (fd_vinyl_client_t) {
      .rq        = rq,
      .cq        = cq,
      .burst_max = 1UL,
      .seq       = 0UL,
      .link_id   = link_id,
      .laddr0    = (ulong)join_info.shmem,
      .laddr1    = (ulong)join_info.shmem + join_info.page_cnt*join_info.page_sz,
      .quota_rem = quota_max,
      .quota_max = quota_max
    };
    ctx->client_cnt++;

    quota_free -= quota_max;
    burst_free -= burst_max;

    /* Every client_cnt run loop iterations we receive at most:

         sum_clients recv_max = FD_VINYL_RECV_MAX - burst_free

       requests.  To guarantee we processe requests fast enough
       that we never overrun our receive queue, under maximum
       client load, we need to process:

         sum_clients recv_max / client_cnt

       requests per run loop iteration.  We thus set exec_max
       to the ceil sum_clients recv_max / client_cnt. */

    ctx->exec_max = (FD_VINYL_REQ_MAX - burst_free + ctx->client_cnt - 1UL) / ctx->client_cnt;

  } /* client join loop */

}

/* during_housekeeping is called periodically (approx every STEM_LAZY ns) */

static void
during_housekeeping( fd_vinyl_tile_t * ctx ) {

  fd_vinyl_t * vinyl = ctx->vinyl;

  if( FD_UNLIKELY( !ctx->booted ) ) {
    ulong const snapin_state = FD_VOLATILE_CONST( *ctx->snapin_state );
    if( snapin_state!=2UL ) {
      fd_log_sleep( 1e6 ); /* 1 ms */
      return;
    }

    /* Once snapin tile exits, boot up vinyl */
    FD_LOG_INFO(( "booting up vinyl tile" ));

    if( ctx->ring ) {
      vinyl->io = fd_vinyl_io_ur_init( ctx->io_mem, IO_SPAD_MAX, ctx->bstream_fd, ctx->ring );
      if( FD_UNLIKELY( !vinyl->io ) ) FD_LOG_ERR(( "Failed to initialize io_uring I/O backend for account database" ));
    } else {
      vinyl->io = fd_vinyl_io_bd_init( ctx->io_mem, IO_SPAD_MAX, ctx->bstream_fd, 0, NULL, 0UL, 0UL );
      if( FD_UNLIKELY( !vinyl->io ) ) FD_LOG_ERR(( "Failed to initialize blocking I/O backend for account database" ));
    }

    ctx->booted = 1;
  }

  /* If we've written enough to justify appending a parallel
      recovery partition, append one. */

  ulong seq_future = fd_vinyl_io_seq_future( vinyl->io );
  if( FD_UNLIKELY( (seq_future - ctx->seq_part) > vinyl->part_thresh ) ) {

    ulong seq = fd_vinyl_io_append_part( vinyl->io, ctx->seq_part, ctx->accum_dead_cnt, 0UL, NULL, 0UL );
    FD_CRIT( fd_vinyl_seq_eq( seq, seq_future ), "corruption detected" );
    ctx->seq_part = seq + FD_VINYL_BSTREAM_BLOCK_SZ;

    ctx->accum_dead_cnt = 0UL;

    ctx->accum_garbage_cnt++;
    ctx->accum_garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

    fd_vinyl_io_commit( vinyl->io, FD_VINYL_IO_FLAG_BLOCKING );
    FD_MCNT_INC( VINYL, BLOCKS_PART, 1UL );

  }

  /* Let the number of items of garbage generated since the last
     compaction be accum_garbage_cnt and let the steady steady
     average number of live / garbage items in the bstream's past be
     L / G (i.e. L is the average value of pair_cnt).  The average
     number pieces of garbage collected per garbage collection round
     is thus G / (L + G).  If we do compact_max rounds garbage
     collection this async handling, we expect to collect

          compact_max G / (L + G)

     items of garbage on average.  To make sure we collect garbage
     faster than we generate it on average, we then require:

          accum_garbage_cnt <~ compact_max G / (L + G)
       -> compact_max >~ (L + G) accum_garbage_cnt / G

     Let the be 2^-gc_eager be the maximum fraction of items in the
     bstream's past we are willing tolerate as garbage on average.
     We then have G = 2^-gc_eager (L + G).  This implies:

       -> compact_max >~ accum_garbage_cnt 2^gc_eager

     When accum_garbage_cnt is 0, we use a compact_max of 1 to do
     compaction rounds at a minimum rate all the time.  This allows
     transients (e.g. a sudden change to new steady state
     equilibrium, temporary disabling of garbage collection at key
     times for highest performance, etc) and unaccounted zero
     padding garbage to be absorbed when nothing else is going on. */

  int gc_eager = vinyl->gc_eager;
  if( FD_LIKELY( gc_eager>=0 ) ) {

    /* Saturating wide left shift */
    ulong overflow    = (ctx->accum_garbage_cnt >> (63-gc_eager) >> 1); /* sigh ... avoid wide shift UB */
    ulong compact_max = fd_ulong_max( fd_ulong_if( !overflow, ctx->accum_garbage_cnt << gc_eager, ULONG_MAX ), 1UL );

    FD_MCNT_INC( VINYL, CUM_GC_RECORDS, ctx->accum_garbage_cnt );
    FD_MCNT_INC( VINYL, CUM_GC_BYTES,   ctx->accum_garbage_sz  );

    /**/                                        ctx->accum_garbage_cnt = 0UL;
    vinyl->garbage_sz += ctx->accum_garbage_sz; ctx->accum_garbage_sz  = 0UL;

    fd_vinyl_compact( vinyl, compact_max );
    /* FIXME count blocks written during compaction towards metrics */

  }

}

/* If should_shutdown returns non-zero, the vinyl tile is shut down */

static int
should_shutdown( fd_vinyl_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->booted ) ) return 0;
  if( FD_LIKELY( !ctx->shutdown ) ) return 0;

  fd_vinyl_t *    vinyl = ctx->vinyl;
  fd_vinyl_io_t * io    = vinyl->io;

  ulong discard_cnt = ctx->req_tail - ctx->req_head;

  /* Append the final partition and sync so we can resume with a fast
     parallel recovery */

  FD_MCNT_INC( VINYL, BLOCKS_PART, 1UL );
  fd_vinyl_io_append_part( io, ctx->seq_part, ctx->accum_dead_cnt, 0UL, NULL, 0UL );

  ctx->accum_dead_cnt = 0UL;

  ctx->accum_garbage_cnt++;
  ctx->accum_garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

  fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );

  fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );

  /* Drain outstanding accumulators */

  /**/                                        ctx->accum_garbage_cnt = 0UL;
  vinyl->garbage_sz += ctx->accum_garbage_sz; ctx->accum_garbage_sz  = 0UL;

  /* Disconnect from the clients */

  ulong released_cnt = 0UL;
  for( ulong client_idx=0UL; client_idx<ctx->client_cnt; client_idx++ ) {
    released_cnt += (ctx->_client[ client_idx ].quota_max - ctx->_client[ client_idx ].quota_rem);
  }

  if( FD_UNLIKELY( discard_cnt     ) ) FD_LOG_WARNING(( "halt discarded %lu received requests",   discard_cnt     ));
  if( FD_UNLIKELY( released_cnt    ) ) FD_LOG_WARNING(( "halt released %lu outstanding acquires", released_cnt    ));
  if( FD_UNLIKELY( ctx->client_cnt ) ) FD_LOG_WARNING(( "halt disconneced %lu clients",           ctx->client_cnt ));

  return 1;
}

static void
metrics_write( fd_vinyl_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->booted ) ) return;
  fd_vinyl_t *    vinyl = ctx->vinyl;
  fd_vinyl_io_t * io    = vinyl->io;

  FD_MGAUGE_SET( VINYL, BSTREAM_SEQ_ANCIENT, io->seq_ancient );
  FD_MGAUGE_SET( VINYL, BSTREAM_SEQ_PAST,    io->seq_past    );
  FD_MGAUGE_SET( VINYL, BSTREAM_SEQ_PRESENT, io->seq_present );
  FD_MGAUGE_SET( VINYL, BSTREAM_SEQ_FUTURE,  io->seq_future  );

  FD_MGAUGE_SET( VINYL, GARBAGE_RECORDS, ctx->accum_garbage_cnt );
  FD_MGAUGE_SET( VINYL, GARBAGE_BYTES,   ctx->accum_garbage_sz  );
}

/* before_credit runs every main loop iteration */

static void
before_credit( fd_vinyl_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  if( FD_UNLIKELY( !ctx->booted ) ) return;

  fd_vinyl_t * vinyl = ctx->vinyl;

  fd_vinyl_io_t *   io   = vinyl->io;
  fd_vinyl_meta_t * meta = vinyl->meta;
  fd_vinyl_line_t * line = vinyl->line;
  fd_vinyl_data_t * data = vinyl->data;

  ulong pair_max = vinyl->pair_max;

  fd_vinyl_meta_ele_t * ele0       = meta->ele;
  ulong                 ele_max    = meta->ele_max;
  ulong                 meta_seed  = meta->seed;
  ulong *               lock       = meta->lock;
  int                   lock_shift = meta->lock_shift;

  ulong                       data_laddr0 = (ulong)data->laddr0;
  fd_vinyl_data_vol_t const * vol         =        data->vol;
  ulong                       vol_cnt     =        data->vol_cnt;

  ulong line_cnt  = vinyl->line_cnt;

  /* Select client to poll this run loop iteration */

  ctx->client_idx = fd_ulong_if( ctx->client_idx+1UL<ctx->client_cnt, ctx->client_idx+1UL, 0UL );

  fd_vinyl_client_t * client = ctx->_client + ctx->client_idx;

  fd_vinyl_rq_t * rq        = client->rq;
  ulong           seq       = client->seq;
  ulong           burst_max = client->burst_max;
  ulong           link_id   = client->link_id;

  ulong accum_dead_cnt    = ctx->accum_dead_cnt;
  ulong accum_garbage_cnt = ctx->accum_garbage_cnt;
  ulong accum_garbage_sz  = ctx->accum_garbage_sz;

  /* Enqueue up to burst_max requests from this client into the
     local request queue.  Using burst_max << FD_VINYL_REQ_MAX
     allows applications to prevent a bursty client from starving
     other clients of resources while preserving the spatial and
     temporal locality of reasonably sized O(burst_max) bursts from
     an individual client in processing below.  Each run loop
     iteration can enqueue up to burst_max requests per iterations. */

  for( ulong recv_rem=fd_ulong_min( FD_VINYL_REQ_MAX-(ctx->req_tail-ctx->req_head), burst_max ); recv_rem; recv_rem-- ) {
    fd_vinyl_req_t * req = ctx->_req + (ctx->req_tail & (FD_VINYL_REQ_MAX-1UL));

    long diff = fd_vinyl_rq_recv( rq, seq, req );

    if( FD_LIKELY( diff>0L ) ) break; /* No requests waiting in rq at this time */

    if( FD_UNLIKELY( diff ) ) FD_LOG_CRIT(( "client overran request queue" ));

    *charge_busy = 1;
    seq++;

    /* We got the next request.  Decide if we should accept it.

       Specifically, we ignore requests whose link_id don't match
       link_id (e.g. an unknown link_id or matches a different
       client's link_id ... don't know if it is where or even if it
       is safe to the completion).  Even if the request provided an
       out-of-band location to send the completion (comp_gaddr!=0),
       we have no reason to trust it given the mismatch.

       This also gives a mechanism for a client use a single rq to
       send requests to multiple vinyl instances ... the client
       should use a different link_id for each vinyl instance.  Each
       vinyl instance will quickly filter out the requests not
       addressed to it.

       Since we know the client_idx at this point, given a matching
       link_id, we stash the client_idx in the pending req link_id
       to eliminate the need to maintain a link_id<>client_idx map
       in the execution loop below. */

    if( FD_UNLIKELY( req->link_id!=link_id ) ) {
      FD_LOG_CRIT(( "received request from link_id %lu, but request specifies incorrect link_id %lu",
                    link_id, req->link_id ));
    }

    req->link_id = ctx->client_idx;

    ctx->req_tail++;
  }

  client->seq = seq;

  /* Execute received requests */

  for( ulong exec_rem=fd_ulong_min( ctx->req_tail-ctx->req_head, ctx->exec_max ); exec_rem; exec_rem-- ) {
    fd_trace_request_batch_enter();
    fd_vinyl_req_t * req = ctx->_req + ((ctx->req_head++) & (FD_VINYL_REQ_MAX-1UL));

    /* Determine the client that sent this request and unpack the
       completion fields.  We ignore requests with non-NULL but
       unmappable out-of-band completion because we can't send the
       completion in the expected manner and, in lieu of that, the
       receivers aren't expecting any completion to come via the cq
       (if any).  Note that this implies requests that don't produce a
       completion (e.g. FETCH and FLUSH) need to either provide NULL
       or a valid non-NULL location for comp_gaddr to pass this
       validation (this is not a burden practically). */

    ulong  req_id     =        req->req_id;
    ulong  client_idx =        req->link_id; /* See note above about link_id / client_idx conversion */
    ulong  batch_cnt  = (ulong)req->batch_cnt;
    ulong  comp_gaddr =        req->comp_gaddr;

    fd_vinyl_client_t * client = ctx->_client + client_idx;

    fd_vinyl_cq_t * cq            = client->cq;
    ulong           link_id       = client->link_id;
    ulong           client_laddr0 = client->laddr0;
    ulong           client_laddr1 = client->laddr1;
    ulong           quota_rem     = client->quota_rem;

    FD_CRIT( quota_rem<=client->quota_max, "corruption detected" );

    fd_vinyl_comp_t * comp = MAP_REQ_GADDR( comp_gaddr, fd_vinyl_comp_t, 1UL );
    if( FD_UNLIKELY( (!comp) & (!!comp_gaddr) ) ) {
      FD_LOG_CRIT(( "client with link_id=%lu requested completion at invalid gaddr %lu",
                    link_id, comp_gaddr ));
    }

    int   comp_err   = 1;
    ulong fail_cnt   = 0UL;

    ulong read_cnt   = 0UL;
    ulong append_cnt = 0UL;

    switch( req->type ) {

#   include "../../vinyl/fd_vinyl_case_acquire.c"
#   include "../../vinyl/fd_vinyl_case_release.c"
    /* FIXME support more request types */

    default:
      FD_LOG_CRIT(( "unsupported request type %u", (uint)req->type ));
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    FD_MCNT_INC( VINYL, REQUEST_BATCHES, 1UL );
    switch( req->type ) {
    case FD_VINYL_REQ_TYPE_ACQUIRE:
      FD_MCNT_INC( VINYL, REQUESTS_ACQUIRE, batch_cnt );
      break;
    case FD_VINYL_REQ_TYPE_RELEASE:
      FD_MCNT_INC( VINYL, REQUESTS_RELEASE, batch_cnt );
      break;
    }

    for( ; read_cnt; read_cnt-- ) {
      fd_vinyl_io_rd_t * _rd; /* avoid pointer escape */
      fd_trace_io_poll_enter();
      fd_vinyl_io_poll( io, &_rd, FD_VINYL_IO_FLAG_BLOCKING );
      fd_trace_io_poll_exit();
      fd_vinyl_io_rd_t * rd = _rd;

      fd_vinyl_data_obj_t *     obj      = (fd_vinyl_data_obj_t *)    rd->ctx;
      ulong                     seq      =                            rd->seq; (void)seq;
      fd_vinyl_bstream_phdr_t * cphdr    = (fd_vinyl_bstream_phdr_t *)rd->dst;
      ulong                     cpair_sz =                            rd->sz;  (void)cpair_sz;

      fd_vinyl_data_obj_t * cobj = (fd_vinyl_data_obj_t *)fd_ulong_align_dn( (ulong)rd, FD_VINYL_BSTREAM_BLOCK_SZ );

      FD_CRIT( cphdr==fd_vinyl_data_obj_phdr( cobj ), "corruption detected" );

      ulong cpair_ctl = cphdr->ctl;

      int   cpair_type    = fd_vinyl_bstream_ctl_type ( cpair_ctl );
      int   cpair_style   = fd_vinyl_bstream_ctl_style( cpair_ctl );
      ulong cpair_val_esz = fd_vinyl_bstream_ctl_sz   ( cpair_ctl );

      FD_CRIT( cpair_type==FD_VINYL_BSTREAM_CTL_TYPE_PAIR,            "corruption detected" );
      FD_CRIT( cpair_sz  ==fd_vinyl_bstream_pair_sz( cpair_val_esz ), "corruption detected" );

      schar * rd_err = cobj->rd_err;

      FD_CRIT ( rd_err,                                          "corruption detected" );
      FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );

      ulong line_idx = obj->line_idx;

      FD_CRIT( line_idx<line_cnt,                 "corruption detected" );
      FD_CRIT( line[ line_idx ].obj==obj,         "corruption detected" );

      ulong ele_idx = line[ line_idx ].ele_idx;

      FD_CRIT ( ele_idx<ele_max,                                                          "corruption detected" );
      FD_ALERT( !memcmp( &ele0[ ele_idx ].phdr, cphdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );
      FD_CRIT ( ele0[ ele_idx ].seq     ==seq,                                            "corruption detected" );
      FD_CRIT ( ele0[ ele_idx ].line_idx==line_idx,                                       "corruption detected" );

      /* Verify data integrity */

      FD_ALERT( !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)cphdr, cpair_sz ), "corruption detected" );

      /* Decode the pair */

      char * val    = (char *)fd_vinyl_data_obj_val( obj );
      ulong  val_sz = (ulong)cphdr->info.val_sz;

      FD_CRIT( val_sz <= FD_VINYL_VAL_MAX,                 "corruption detected" );
      FD_CRIT( fd_vinyl_data_obj_val_max( obj ) >= val_sz, "corruption detected" );

      if( FD_LIKELY( cpair_style==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) {

        FD_CRIT( obj==cobj,             "corruption detected" );
        FD_CRIT( cpair_val_esz==val_sz, "corruption detected" );

      } else {

        char const * cval    = (char const *)fd_vinyl_data_obj_val( cobj );
        ulong        cval_sz = fd_vinyl_bstream_ctl_sz( cpair_ctl );

        ulong _val_sz = (ulong)LZ4_decompress_safe( cval, val, (int)cval_sz, (int)val_sz );
        if( FD_UNLIKELY( _val_sz!=val_sz ) ) FD_LOG_CRIT(( "LZ4_decompress_safe failed" ));

        fd_vinyl_data_free( data, cobj );

        fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

        phdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
        phdr->key  = cphdr->key;
        phdr->info = cphdr->info;

      }

      obj->rd_active = (short)0;

      /* Fill any trailing region with zeros (there is at least
         FD_VINYL_BSTREAM_FTR_SZ) and tell the client the item was
         successfully processed. */

      memset( val + val_sz, 0, fd_vinyl_data_szc_obj_footprint( (ulong)obj->szc )
                               - (sizeof(fd_vinyl_data_obj_t) + sizeof(fd_vinyl_bstream_phdr_t) + val_sz) );

      FD_COMPILER_MFENCE();
      *rd_err = (schar)FD_VINYL_SUCCESS;
      FD_COMPILER_MFENCE();

    }

    if( FD_UNLIKELY( append_cnt ) ) fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );

    if( FD_LIKELY( comp_err<=0 ) ) fd_vinyl_cq_send( cq, comp, req_id, link_id, comp_err, batch_cnt, fail_cnt, quota_rem );

    client->quota_rem = quota_rem;

    /* Update metrics.  Derive counters from vinyl locals

      append_cnt is incremented in these places:
      - fd_vinyl_case_erase.c   (fd_vinyl_io_append_dead, with accum_dead_cnt)
      - fd_vinyl_case_move.c    (fd_vinyl_io_append_move, with accum_move_cnt)
      - fd_vinyl_case_move.c    (fd_vinyl_io_append(pair))
      - fd_vinyl_case_release.c (fd_vinyl_io_append_pair_inplace)
      - fd_vinyl_case_release.c (fd_vinyl_io_append_dead, with accum_dead_cnt)

      We can thus infer the number of pair blocks appended by
      subtracting accum_* */

    ulong const dead_cnt = accum_dead_cnt - ctx->accum_dead_cnt;
    FD_MCNT_INC( VINYL, BLOCKS_PAIR, append_cnt - dead_cnt );
    FD_MCNT_INC( VINYL, BLOCKS_DEAD, dead_cnt );

    fd_trace_request_batch_exit();
  }

  ctx->accum_dead_cnt    = accum_dead_cnt;
  ctx->accum_garbage_cnt = accum_garbage_cnt;
  ctx->accum_garbage_sz  = accum_garbage_sz;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (10000) /* housekeep every 10 us */
#define STEM_CALLBACK_CONTEXT_TYPE        fd_vinyl_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       fd_vinyl_align()
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown

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
