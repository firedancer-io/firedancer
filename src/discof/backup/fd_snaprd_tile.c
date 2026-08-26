/* fd_snaprd_tile.c is a worker thread for reading accdb disk data.
   This tile is typically either sleeping or doing iowait. */

#include "fd_backup.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"
#include "../../flamenco/accdb/fd_accdb_private.h"
#include "../../tango/fseq/fd_fseq.h"
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>
#include "generated/fd_snaprd_tile_seccomp.h"

#define SNAPRD_STATE_IDLE    0
#define SNAPRD_STATE_READ    1
#define SNAPRD_STATE_DONE    2
#define SNAPRD_STATE_CAPTURE 3 /* sampling accdb partition bounds */
#define SNAPRD_STATE_DRAIN   4 /* waiting for in-flight accdb writes to land */

#define STEM_BURST 64UL /* 64 * 64KiB -> 4MiB */
#define SNAPRD_PART_MAX (1UL<<13)
#define BARRIER_WORDS   (FD_ACCDB_MAX_JOINERS/64UL)

struct fd_snaprd {
  uint state;

  /* control signal from snapmk, which wakes up the tile */
  atomic_ulong * in_ctl;
  ulong          in_ctl_seq;

  ulong idle_cnt;

  fd_accdb_shmem_t const * accdb;

  /* these are valid while reading a snapshot of accdb partition bounds */
  struct {
    ulong file_off;
    ulong sz;
  } part[ SNAPRD_PART_MAX ];
  ulong part_cnt;
  ulong part_idx;
  ulong part_cur;      /* cursor in [0,part_sz] */
  ulong part_sz;       /* byte size of partition */
  ulong part_file_off; /* accdb file offset of partition */

  ulong barrier[ BARRIER_WORDS ]; /* writers whose pwritev2 has yet to land */

  struct {
    void * mem;
    ulong  chunk0;
    ulong  wmark;
    ulong  chunk;
    ulong  mtu;
  } out;

  struct {
    ulong bytes_read;
    ulong export_progress_bytes;
    ulong export_total_bytes;
    ulong io_blocked_ticks;
  } metrics;
};

typedef struct fd_snaprd fd_snaprd_t;

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO; /* accounts db readonly fd */
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_snaprd_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)FD_ACCDB_FD_RO );
  return sock_filter_policy_fd_snaprd_tile_instr_cnt;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_snaprd_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_snaprd_t);
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_snaprd_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ctx->state      = SNAPRD_STATE_IDLE;
  ctx->in_ctl     = NULL;
  ctx->in_ctl_seq = 0UL;
  ctx->idle_cnt   = 0UL;
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  /* snaprd queries accdb partition info to figure out where to read */
  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snaprd.accdb_obj_id );
  ctx->accdb = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( ctx->accdb );

  FD_CHECK_ERR( tile->out_cnt==1UL, "topology mismatch" );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_CHECK_ERR( !strcmp( out_link->name, "snaprd_out" ), "topology mismatch" );
  FD_CHECK_ERR( out_link->mtu && out_link->mtu<=UINT_MAX, "topology mismatch" );


  ulong snapmk_tile_id = fd_topo_find_tile( topo, "snapmk", 0UL );
  FD_CHECK_ERR( snapmk_tile_id!=ULONG_MAX, "missing snapmk tile" );
  fd_topo_tile_t const * snapmk_tile = &topo->tiles[ snapmk_tile_id ];

  ulong snapmk_in_idx = fd_topo_find_tile_in_link( topo, snapmk_tile, "snaprd_out", out_link->kind_id );
  FD_CHECK_ERR( snapmk_in_idx!=ULONG_MAX, "missing snapmk input link for snaprd_out" );
  FD_CHECK_ERR( snapmk_tile->in_link_reliable[ snapmk_in_idx ], "snaprd_out consumer is not reliable" );

  ulong * fseq = fd_fseq_join( fd_topo_obj_laddr( topo, snapmk_tile->in_link_fseq_obj_id[ snapmk_in_idx ] ) );
  FD_TEST( fseq );
  ctx->in_ctl = fd_fseq_app_laddr( fseq );
  FD_STATIC_ASSERT( sizeof(ulong)<=FD_FSEQ_APP_FOOTPRINT, fseq_app_space );
  ctx->in_ctl_seq = atomic_load_explicit( ctx->in_ctl, memory_order_acquire );

  ctx->out.mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.mem, out_link->dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark( ctx->out.mem, out_link->dcache, out_link->mtu );
  ctx->out.chunk  = ctx->out.chunk0;
  ctx->out.mtu    = out_link->mtu;
}

static int
next_partition( fd_snaprd_t * ctx ) {
  while( ctx->part_idx<ctx->part_cnt ) {
    ulong part_idx = ctx->part_idx++;
    if( FD_UNLIKELY( !ctx->part[ part_idx ].sz ) ) continue;
    ctx->part_cur      = 0UL;
    ctx->part_sz       = ctx->part[ part_idx ].sz;
    ctx->part_file_off = ctx->part[ part_idx ].file_off;
    return 1;
  }

  ctx->part_cur      = 0UL;
  ctx->part_sz       = 0UL;
  ctx->part_file_off = 0UL;
  return 0;
}

/* backup_disk_capture determines which accdb partition ranges must be
   read to produce a snapshot. */

static int
backup_disk_capture( fd_snaprd_t * ctx ) {
  ulong part_max = fd_accdb_shmem_partition_max( ctx->accdb );
  if( FD_UNLIKELY( part_max>SNAPRD_PART_MAX ) ) {
    FD_LOG_ERR(( "accdb partition count %lu exceeds snaprd capacity %lu", part_max, SNAPRD_PART_MAX ));
  }

  ulong part_sz = fd_accdb_shmem_partition_sz( ctx->accdb );
  fd_accdb_partition_t const * pool = (fd_accdb_partition_t const *)( (uchar const *)ctx->accdb + ctx->accdb->partition_pool_off );

  ctx->part_cnt = 0UL;
  ulong export_total_bytes = 0UL;
  for( ulong i=0UL; i<part_max; i++ ) {
    /* the accdb partitions might grow after we save offsets into
       ctx->part, but we can safely ignore any future data (newly added
       rooted accounts will have been saved from cache, and non-rooted
       accounts are ignored regardless) */

    ulong sz = ULONG_MAX;
    for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
      if( !FD_VOLATILE_CONST( ctx->accdb->has_partition[ k ] ) ) continue;
      accdb_offset_t whead = { .val = FD_VOLATILE_CONST( ctx->accdb->whead[ k ].val ) };
      if( packed_partition_idx( &whead )!=i ) continue;
      sz = packed_partition_offset( &whead );
      if( FD_UNLIKELY( sz>ctx->accdb->partition_sz ) ) return 0;
      break;
    }
    if( sz==ULONG_MAX ) sz = FD_VOLATILE_CONST( partition_pool_ele_const( pool, i )->write_offset );

    if( !sz ) continue;
    ctx->part[ ctx->part_cnt ].file_off = i*part_sz;
    ctx->part[ ctx->part_cnt ].sz       = sz;
    ctx->part_cnt++;
    export_total_bytes += sz;
  }
  ctx->metrics.export_progress_bytes = 0UL;
  ctx->metrics.export_total_bytes    = export_total_bytes;

  /* need to wait for these writers to complete */
  memset( ctx->barrier, 0, sizeof(ctx->barrier) );
  ulong joiner_cnt = FD_VOLATILE_CONST( ctx->accdb->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    if( FD_VOLATILE_CONST( ctx->accdb->joiner_epochs[ t ].val )==ULONG_MAX ) continue;
    ctx->barrier[ t/64UL ] |= 1UL<<(t%64UL);
  }
  return 1;
}

/* backup_disk_drain waits out the writes that were in flight when
   backup_disk_capture sampled the partition bounds. */

static void
backup_disk_drain( fd_snaprd_t * ctx ) {
  ulong remain = 0UL;
  for( ulong w=0UL; w<BARRIER_WORDS; w++ ) {
    ulong bits = ctx->barrier[ w ];
    while( bits ) {
      ulong b = (ulong)fd_ulong_find_lsb( bits );
      bits &= bits-1UL;
      if( FD_VOLATILE_CONST( ctx->accdb->joiner_epochs[ w*64UL+b ].val )==ULONG_MAX ) {
        ctx->barrier[ w ] &= ~(1UL<<b);
      }
    }
    remain |= ctx->barrier[ w ];
  }
  if( FD_UNLIKELY( remain ) ) return;

  /* An accdb with no data on disk yields an empty stream, which snapmk
     still has to see terminated (a zero size frag carrying eom). */
  ctx->part_idx = 0UL;
  next_partition( ctx );
  ctx->state = SNAPRD_STATE_READ;
}

static void
before_credit( fd_snaprd_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem; (void)charge_busy;

  ulong ctl_cur  = atomic_load_explicit( ctx->in_ctl, memory_order_acquire );
  ulong ctl_prev = ctx->in_ctl_seq;
  if( FD_LIKELY( ctl_prev==ctl_cur ) ) {
    if( FD_UNLIKELY( ctx->idle_cnt++ > 16384UL ) ) fd_log_sleep( (long)1e6 );
    return;
  }

  /* new backup job */
  ctx->in_ctl_seq = ctl_cur;
  ctx->state      = SNAPRD_STATE_CAPTURE;
  ctx->idle_cnt   = 0UL;
  *charge_busy = 1;
}

static void
after_credit( fd_snaprd_t *       ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( ctx->state==SNAPRD_STATE_CAPTURE ) ) {
    *charge_busy = 1;
    if( FD_UNLIKELY( !backup_disk_capture( ctx ) ) ) return;
    ctx->state = SNAPRD_STATE_DRAIN;
    return;
  }

  if( FD_UNLIKELY( ctx->state==SNAPRD_STATE_DRAIN ) ) {
    *charge_busy = 1;
    backup_disk_drain( ctx );
    return;
  }

  if( FD_UNLIKELY( ctx->state!=SNAPRD_STATE_READ ) ) return;

  FD_CHECK_CRIT( *stem->cr_avail <= UINT_MAX, "cr_avail underflow" );
  FD_CHECK_CRIT( ctx->part_cur <= ctx->part_sz, "partition cursor overflow" );

  ulong burst_rem = STEM_BURST;
  while( ctx->state==SNAPRD_STATE_READ && stem->cr_avail[ 0 ] && burst_rem-- ) {
    ulong frag_sz = fd_ulong_min( ctx->out.mtu, ctx->part_sz-ctx->part_cur );

    ulong   chunk   = ctx->out.chunk;
    uchar * out     = fd_chunk_to_laddr( ctx->out.mem, chunk );
    ulong   src_off = ctx->part_file_off + ctx->part_cur;

    ulong read_sz = 0UL;
    long  t0      = fd_tickcount();
    while( read_sz<frag_sz ) {
      long res = pread( FD_ACCDB_FD_RO, out+read_sz, frag_sz-read_sz, (long)(src_off+read_sz) );
      if( FD_UNLIKELY( res<0L && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK) ) ) continue;
      if( FD_UNLIKELY( res<0L ) ) {
        FD_LOG_ERR(( "pread failed: %i-%s", errno, fd_io_strerror( errno ) ));
      }
      if( FD_UNLIKELY( !res ) ) {
        FD_LOG_ERR(( "pread returned EOF at offset %lu", src_off+read_sz ));
      }
      read_sz += (ulong)res;
    }
    long t1 = fd_tickcount();
    ctx->metrics.bytes_read            += read_sz;
    ctx->metrics.export_progress_bytes += read_sz;
    if( FD_LIKELY( frag_sz ) ) ctx->metrics.io_blocked_ticks += (ulong)( t1-t0 );

    ctx->part_cur += frag_sz;

    int eom = 0;
    if( FD_UNLIKELY( ctx->part_cur==ctx->part_sz && !next_partition( ctx ) ) ) {
      ctx->state = SNAPRD_STATE_DONE;
      eom = 1;
    }

    ulong sz    = fd_ulong_min( frag_sz, (ulong)USHORT_MAX );
    ulong ctl   = fd_frag_meta_ctl( FD_BACKUP_ORIG_DISK_FRAG, 0, eom, 0 );
    ulong tspub = frag_sz;
    fd_stem_publish( stem, 0UL, src_off, chunk, sz, ctl, 0UL, tspub );
    ctx->out.chunk = fd_dcache_compact_next( chunk, frag_sz, ctx->out.chunk0, ctx->out.wmark );

    ctx->idle_cnt = 0UL;
    *charge_busy = 1;
    *opt_poll_in = 0;
  }
}

static void
metrics_write( fd_snaprd_t * ctx ) {
  FD_MCNT_SET  ( SNAPRD, BYTES_READ,                  ctx->metrics.bytes_read             );
  FD_MGAUGE_SET( SNAPRD, EXPORT_PROGRESS_BYTES,       ctx->metrics.export_progress_bytes );
  FD_MGAUGE_SET( SNAPRD, EXPORT_TOTAL_BYTES,          ctx->metrics.export_total_bytes    );
  FD_MCNT_SET  ( SNAPRD, IO_BLOCKED_DURATION_SECONDS, ctx->metrics.io_blocked_ticks      );
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_t)
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaprd = {
  .name                     = "snaprd",
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
