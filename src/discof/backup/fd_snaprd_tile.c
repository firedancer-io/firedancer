#include "fd_backup.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"
#include <errno.h>
#include <unistd.h>

#define SNAPRD_STATE_IDLE 0
#define SNAPRD_STATE_READ 1
#define SNAPRD_STATE_DONE 2

#define STEM_BURST 64UL /* 64 * 64KiB -> 4MiB */
#define SNAPRD_PART_MAX (1UL<<13)

struct fd_snaprd {
  uint state;

  ulong idle_cnt;

  fd_accdb_shmem_t const * accdb;
  ulong volatile const *   snapmk_state;

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

  ctx->state    = SNAPRD_STATE_IDLE;
  ctx->idle_cnt = 0UL;

  /* snaprd queries accdb partition info to figure out where to read */
  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snaprd.accdb_obj_id );
  ctx->accdb = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( ctx->accdb );

  /* Monitor snapmk state as an edge trigger
     (When snapmk is done reading the cache, start reading disk data) */
  ulong snapmk_tile_id = fd_topo_find_tile( topo, "snapmk", 0UL );
  FD_TEST( snapmk_tile_id!=ULONG_MAX );
  fd_topo_tile_t const * snapmk_tile = &topo->tiles[ snapmk_tile_id ];
  ulong * snapmk_metrics = fd_metrics_join( fd_topo_obj_laddr( topo, snapmk_tile->metrics_obj_id ) );
  FD_TEST( snapmk_metrics );
  ctx->snapmk_state = &fd_metrics_tile( snapmk_metrics )[ MIDX( GAUGE, SNAPMK, STATE ) ];

  FD_CHECK_ERR( tile->out_cnt==1UL, "topology mismatch" );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_CHECK_ERR( !strcmp( out_link->name, "snaprd_out" ), "topology mismatch" );
  FD_CHECK_ERR( out_link->mtu && out_link->mtu<=UINT_MAX, "topology mismatch" );
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

static void
backup_disk_begin( fd_snaprd_t * ctx ) {
  ulong job_read_total = 0UL;
  ulong part_max = fd_accdb_shmem_partition_max( ctx->accdb );
  if( FD_UNLIKELY( part_max>SNAPRD_PART_MAX ) ) {
    FD_LOG_ERR(( "accdb partition count %lu exceeds snaprd capacity %lu", part_max, SNAPRD_PART_MAX ));
  }

  ctx->part_cnt = 0UL;
  for( ulong i=0UL; i<part_max; i++ ) {
    fd_accdb_shmem_partition_info_t info[1];
    fd_accdb_shmem_partition_info( ctx->accdb, i, info );
    /* Freeze the byte ranges for this disk pass.  The active accdb
       write head can advance while snaprd is reading; following it live
       would let the parser consume records outside the snapshot pass. */
    ctx->part[ ctx->part_cnt ].file_off = info->file_offset;
    ctx->part[ ctx->part_cnt ].sz       = info->write_offset;
    ctx->part_cnt++;
    job_read_total += info->write_offset;
  }
  ctx->metrics.export_total_bytes    = job_read_total;
  ctx->metrics.export_progress_bytes = 0UL;

  ctx->part_idx = 0UL;
  ctx->state = fd_uint_if( next_partition( ctx ), SNAPRD_STATE_READ, SNAPRD_STATE_DONE );
}

static void
before_credit( fd_snaprd_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem; (void)charge_busy;

  ulong snapmk_state = FD_VOLATILE_CONST( *ctx->snapmk_state );
  if( FD_UNLIKELY( ctx->state==SNAPRD_STATE_IDLE && snapmk_state==SNAPMK_STATE_ACCOUNTS_DISK ) ) {
    backup_disk_begin( ctx );
    ctx->idle_cnt = 0UL;
    return;
  }

  if( FD_UNLIKELY( ctx->state==SNAPRD_STATE_DONE && !snapmk_state ) ) {
    ctx->state = SNAPRD_STATE_IDLE;
    ctx->idle_cnt = 0UL;
    return;
  }

  // if( FD_UNLIKELY( ctx->idle_cnt++ > 65536UL ) ) {
  //   fd_log_sleep( (long)1e6 );
  // }
}

static void
after_credit( fd_snaprd_t *       ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( ctx->state!=SNAPRD_STATE_READ ) ) return;

  FD_CHECK_CRIT( *stem->cr_avail <= UINT_MAX, "cr_avail underflow" );
  FD_CHECK_CRIT( ctx->part_cur <= ctx->part_sz, "partition cursor overflow" );

  ulong burst_rem = STEM_BURST;
  while( ctx->state==SNAPRD_STATE_READ && stem->cr_avail[ 0 ] && burst_rem-- ) {
    ulong frag_sz = fd_ulong_min( ctx->out.mtu, ctx->part_sz-ctx->part_cur );
    if( FD_UNLIKELY( !frag_sz ) ) {
      if( FD_UNLIKELY( !next_partition( ctx ) ) ) ctx->state = SNAPRD_STATE_DONE;
      continue;
    }

    ulong   chunk   = ctx->out.chunk;
    uchar * out     = fd_chunk_to_laddr( ctx->out.mem, chunk );
    ulong   src_off = ctx->part_file_off + ctx->part_cur;

    ulong read_sz = 0UL;
    while( read_sz<frag_sz ) {
      long res = pread( FD_ACCDB_FD_RO, out+read_sz, frag_sz-read_sz, (long)(src_off+read_sz) );
      if( FD_UNLIKELY( res<0L ) ) {
        FD_LOG_ERR(( "pread failed: %i-%s", errno, fd_io_strerror( errno ) ));
      }
      if( FD_UNLIKELY( !res ) ) {
        FD_LOG_ERR(( "pread returned EOF at offset %lu", src_off+read_sz ));
      }
      read_sz += (ulong)res;
    }

    ctx->part_cur += frag_sz;
    ctx->metrics.bytes_read            += frag_sz;
    ctx->metrics.export_progress_bytes += frag_sz;

    int eom = 0;
    if( FD_UNLIKELY( ctx->part_cur==ctx->part_sz && !next_partition( ctx ) ) ) {
      ctx->state = SNAPRD_STATE_DONE;
      eom = 1;
    }

    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DISK_FRAG, 0, eom, 0 );
    fd_stem_publish( stem, 0UL, src_off, chunk,
                     fd_ulong_min( frag_sz, (ulong)USHORT_MAX ),
                     ctl, 0UL, frag_sz );
    ctx->out.chunk = fd_dcache_compact_next( chunk, frag_sz, ctx->out.chunk0, ctx->out.wmark );

    ctx->idle_cnt = 0UL;
    *charge_busy = 1;
    *opt_poll_in = 0;
  }
}

static void
metrics_write( fd_snaprd_t * ctx ) {
  FD_MGAUGE_SET( SNAPRD, STATE,                 ctx->state                         );
  FD_MCNT_SET  ( SNAPRD, BYTES_READ,            ctx->metrics.bytes_read            );
  FD_MGAUGE_SET( SNAPRD, EXPORT_PROGRESS_BYTES, ctx->metrics.export_progress_bytes );
  FD_MGAUGE_SET( SNAPRD, EXPORT_TOTAL_BYTES,    ctx->metrics.export_total_bytes    );
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_t)
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaprd = {
  .name                 = "snaprd",
  .populate_allowed_fds = populate_allowed_fds,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .allow_renameat       = 1
};
