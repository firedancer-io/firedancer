/* The snapmk tile coordinates snapshot production.

   snapmk discovers accounts (zero copy) and generates compression jobs
   for downstream snapzp tiles (load balanced).

   snapmk uses snaprd as a worker thread.  The snapmk's snaprd_out fseq
   has an application region, which indicates when snaprd should spring
   into action.  Once activated, it reads all accdb partitions into a
   ring buffer (mcache/dcache).  snaprd is a separate worker thread
   because otherwise, snapmk would be blocked on synchronous I/O and
   waste time copying data.

   Finally, snapmk interfaces with the replay tile.  The replay tile
   instructs when to produce a snapshot, snapmk takes ownership of the
   pipeline / state machine, and notifies the replay tile when snap
   production is done.

   ### File management

   All snap producer tile processes (or threads) in a Firedancer
   instance share a fixed pool of file descriptors for snapshot file
   descriptors.

   These FDs are visible under proper snapshot file names
   (e.g. "snapshot-433132190-8cSwtWwmkj3oaXPsyUxhL1QkuaAVY1S4vRhqL6EJQ99Z.tar.zst")
   or placeholders (e.g. ".snapshot-x67.partial").  Old snapshots
   eventually get recycled.

   The snapmk tile manages these file descriptors (decides which snaps
   to select for new creations, which ones to recycle, etc).

   ### Zero copy snaprd->mk->zp path

   The snaprd tile reads accdb data into memory at high bandwidth.
   The snapmk tile does streaming parsing of this input data, and then
   distributes compression jobs to downstream snapzp tiles.  Those
   compression jobs are mere pointers to the snaprd data.  Thus, snaprd
   must not only backpressure on slow snapmk but slow snapzps too.

   The snapmk tile achieves this by tracking the snapzp job -> snaprd
   frag seq in rd_shadow. */

#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>

#include "fd_snapmk_tile.h"
#include "fd_backup.h"
#include "fd_snap_pool.h"
#include "fd_backup_cache.h"
#include "fd_backup_disk.h"
#include "fd_backup_visited.h"
#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../fd_startup.h"
#include "../replay/fd_replay_tile.h"
#include "../restore/utils/fd_ssarchive.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../tango/fseq/fd_fseq.h"

#include <time.h> /* CLOCK_REALTIME */
#include "generated/fd_snapmk_tile_seccomp.h"

#define RAW_BUF_SZ   (32UL<<20)
#define COMP_BUF_SZ  ZSTD_COMPRESSBOUND( RAW_BUF_SZ )

/* FD_SNAPMK_ZP_DEPTH must match the snapmk_zp link depth in topology.c.
   Asserted at init.  Sizes the per-link snaprd-seq shadow rings. */
#define FD_SNAPMK_ZP_DEPTH 1024

/* Max number of reliable snapmk_out consumers */
#define SNAPMK_OUT_CONS_MAX 64

/* SNAPMK_STEM_BURST: number of snapmk_out frags published in one event
   loop cycle (snapmk_zp links are exempt) */
#define SNAPMK_STEM_BURST 3UL
#define SNAPMK_STEM_LAZY  8700UL

/* snapmk lifecycle states */
#define SNAPMK_STATE_IDLE                0 /* clean, waiting for job */
#define SNAPMK_STATE_START               1
#define SNAPMK_STATE_TAR_HEADERS         2
#define SNAPMK_STATE_MANIFEST            3 /* writing manifest */
#define SNAPMK_STATE_ACCDB_CACHE         4 /* writing cached accounts */
#define SNAPMK_STATE_ACCDB_CACHE_FLUSH   5 /* flushing cached accounts */
#define SNAPMK_STATE_ACCDB_CACHE_FINISH  6 /* wait for flush to complete */
#define SNAPMK_STATE_ACCDB_DISK          7 /* writing on-disk accounts */
#define SNAPMK_STATE_ACCDB_DISK_FLUSH    8 /* flushing on-disk accounts */
#define SNAPMK_STATE_ACCDB_DISK_FINISH   9 /* wait for flush to complete */
#define SNAPMK_STATE_ACCDB_DELTA        10 /* writing incremental accounts */
#define SNAPMK_STATE_ACCDB_DELTA_FLUSH  11 /* flushing incremental accounts */
#define SNAPMK_STATE_ACCDB_DELTA_FINISH 12 /* waiting for flush to complete */
#define SNAPMK_STATE_STATUS_CACHE       13 /* writing status cache */
#define SNAPMK_STATE_EOF_MARKER         14 /* writing tar EOF marker */
#define SNAPMK_STATE_DONE               15 /* done, notify replay tile */
#define SNAPMK_STATE_FAIL               16 /* error state, doing cleanup */
#define SNAPMK_STATE_SLEEP              17 /* sleep until FUTEX_WAKE */
#define SNAPMK_STATE_STARTUP            18 /* waiting for system startup */
#define SNAPMK_STATE_STARTUP_BURST      19 /* publish pre-existing snaps */

/* power saving (sleeping) */
#define IDLE_THRES (16384UL)   /* no of idle busy loop iters before sleeping */
#define IDLE_SLEEP ((long)1e6) /* sleep duration (nanoseconds) */

struct fd_snapmk {
  uint state;

  fd_backup_cache_t acc_cache[1];
  visited_set_t *   visited_set;

  /* snapshot files */

  int  snap_fd;     /* current snapshot (-1 if idle) */
  int  snap_dir_fd; /* dirfd to prevent hijacking */
  char snap_dir  [ PATH_MAX ];
  char final_name[ FD_SNAP_NAME_MAX ];
  uint snap_idx; /* in pool */
  uint snap_max;
  uint snap_full_max; /* <=snap_max */
  fd_backup_inode_t pool[ FD_SNAP_MAX ];
  ulong final_sz;

  /* snapzp worker threads */

  ulong          zp_cnt; /* [0,zp_cnt] out links are to zp */
  ulong const *  zp_cons_fseq[ SNAPZP_TILE_MAX ];
  atomic_ulong * file_off_p;

  /* snaprd worker thread */

  atomic_ulong * rd_fseq;
  atomic_ulong * rd_ctl;
  ulong          rd_seq;       /* seq of the snaprd frag last parsed */
  ulong          rd_seq_cache; /* last watermark published to snaprd */
  fd_wksp_t *    rd_in_mem;
  ulong          rd_in_mtu;
  ulong          rd_fseq_dummy;

  /* per zp out link shadow ring: rd_shadow[i][seq%depth] = snaprd seq
     referenced by the mk_zp frag published at seq on link i */
  ulong * rd_shadow[ SNAPZP_TILE_MAX ];

  struct {
    ulong  out_idx;
    void * mem;
    ulong  chunk;
    ulong  chunk0;
    ulong  wmark;

    ulong const * cons_fseq[ SNAPMK_OUT_CONS_MAX ];
    ulong         cons_cnt;
    ulong *       seq_prod;
  } out;

  ulong zp_rr_idx; /* round-robin cursor over zp out links */
  ulong zp_ready;         /* bit set */
  ulong zp_flush_pending; /* bit set */
  ulong zp_barrier[ SNAPZP_TILE_MAX ];

  fd_banks_t *    banks;
  fd_bank_t *     bank;
  fd_txncache_t * txncache;
  fd_ssmanifest_writer_t manifest_writer[1];
  fd_txncache_writer_t   txncache_writer[1];

  ulong manifest_pad;
  ulong status_cache_pad;
  long  start_time;
  ulong last_snapshot_create_slot;

  int   incremental;
  ulong base_slot;

  struct {
    fd_accdb_delta_t const * pool;
    uint const *             chain;
    ulong                    chain_cnt;
    ulong                    chain_idx;
    uint                     ele_idx;
  } delta;

  /* replay in link */

  fd_wksp_t *   replay_in_mem;
  ulong const * replay_in_seq_prod; /* replay_snapmk producer seq */
  ulong         replay_in_seq_cons; /* next expected replay_snapmk seq */
  ulong         idle_iter;          /* busy loop iters spent in IDLE */

  /* IPC */
  struct {
    void * mem;
    ulong  chunk0;
    ulong  wmark;
    ulong  chunk;
  } zp_out[ FD_TOPO_MAX_TILE_OUT_LINKS ];
  fd_backup_cache_msg_t scan_batch[1];
  ushort                in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_snapmk_accparse_t  accparse[1];

  /* disk batch staging (FD_BACKUP_ORIG_ACC_DISK_BATCH).  A batch is
     staged out of the parser, then flushed to a zp tile once an output
     link has credit.  disk_batch_pending guards against re-staging while
     a staged batch is awaiting credit. */
  fd_backup_disk_batch_msg_t disk_batch[1];
  ulong                      disk_batch_base_gaddr;
  int                        disk_batch_pending;
  int                        disk_out_idx; /* snapzp output */

  /* account data cache */
  uchar * cache    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong   cache_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* accdb shared memory */
  fd_accdb_shmem_t *            accdb_shmem;
  fd_accdb_fork_shmem_t const * accdb_shfork;
  fd_accdb_fork_id_t const *    accdb_root_fork;
  ulong *                       accdb_snapshot_sync;

  /* output buffer */
  ZSTD_CCtx *    zst;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;
  uchar raw [ RAW_BUF_SZ  ];
  uchar comp[ COMP_BUF_SZ ];

  /* startup related */
  fd_startup_gate_t startup_gate[1];
  ulong             startup_pool_idx;

  struct {
    ulong snapshots_created_full;
    ulong snapshots_created_incremental;
    ulong last_snapshot_slot_started_full;
    ulong last_snapshot_slot_started_incremental;
    ulong last_snapshot_slot_finished_full;
    ulong last_snapshot_slot_finished_incremental;
    ulong bytes_compressed;
    ulong bytes_written;
    ulong io_blocked_ticks;
    ulong compress_ticks;
  } metrics;
};

typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1
#define IN_KIND_SNAPRD 2

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_snapmk_t), 32UL ), fd_txncache_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong max_live_slots = tile->snapmk.max_live_slots;

  ulong zp_cnt = tile->out_cnt - 1UL; /* last out link is snapmk_out */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t)                              );
  l = FD_LAYOUT_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL ) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots )          );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),       zp_cnt*FD_SNAPMK_ZP_DEPTH*sizeof(ulong)          );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  fd_cstr_ncpy( ctx->snap_dir, tile->snapmk.snapshots_path, PATH_MAX );

  int dir_fd = open( ctx->snap_dir, O_RDONLY|O_DIRECTORY );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", ctx->snap_dir, fd_io_strerror( errno ) ));
  }
  ctx->snap_dir_fd = dir_fd;
  ctx->snap_fd     = -1;

  ctx->snap_full_max = tile->snapmk.max_full_snapshots_to_keep;
  ctx->snap_max      = tile->snapmk.max_full_snapshots_to_keep+
                       tile->snapmk.max_incremental_snapshots_to_keep;
  ctx->snap_idx      = UINT_MAX;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<3UL+(ulong)ctx->snap_max ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->snap_dir_fd;
  for( uint i=0U; i<ctx->snap_max; i++ )
    out_fds[ out_cnt++ ] = FD_SNAP_FD( i ); /* snapshot pool */
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_snapmk_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->snap_dir_fd,
      (uint)FD_SNAP_FD( 0 ), (uint)FD_SNAP_FD( ctx->snap_max-1U ) );
  return sock_filter_policy_fd_snapmk_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong max_live_slots = tile->snapmk.max_live_slots;

  ulong zp_cnt = tile->out_cnt - 1UL;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapmk_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  void *        _zstd    = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL ) );
  void *        _txnc_lj = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots ) );
  ulong *       _rd_shdw = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),       zp_cnt*FD_SNAPMK_ZP_DEPTH*sizeof(ulong) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_CHECK_CRIT( end==(ulong)scratch + scratch_footprint( tile ), "bug when calculating tile memory layout" );

  for( ulong i=0UL; i<zp_cnt; i++ ) {
    ctx->rd_shadow[ i ] = _rd_shdw + i*FD_SNAPMK_ZP_DEPTH;
  }

  ctx->state              = SNAPMK_STATE_STARTUP;
  ctx->replay_in_seq_cons = ULONG_MAX;
  ctx->idle_iter          = 0UL;

  fd_startup_gate_init( ctx->startup_gate, topo, tile->in_cnt );
  ctx->startup_pool_idx = 0UL;

  ctx->incremental = 0;
  ctx->base_slot   = ULONG_MAX;
  ctx->visited_set = visited_set_join( fd_topo_obj_laddr( topo, tile->snapmk.visited_set_obj_id ) );
  FD_TEST( ctx->visited_set );

  ulong banks_obj_id = tile->snapmk.banks_obj_id;
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  fd_txncache_shmem_t * tc_shmem = fd_txncache_shmem_join( fd_topo_obj_laddr( topo, tile->snapmk.txncache_obj_id ) );
  FD_TEST( tc_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txnc_lj, tc_shmem ) );
  FD_TEST( ctx->txncache );

  ulong * zp_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.zp_fseq_id ) ); FD_TEST( zp_fseq );
  ctx->file_off_p = fd_fseq_app_laddr( zp_fseq );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapmk.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  ctx->accdb_shmem = accdb_shmem_ro;
  ctx->accdb_snapshot_sync = &accdb_shmem_ro->snapshot_sync;
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.accdb_epoch_obj_id ) );
  FD_TEST( epoch_fseq );
  fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro, epoch_fseq );
  {
    FD_SCRATCH_ALLOC_INIT( l, accdb_shmem_ro );
    FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN, sizeof(fd_accdb_shmem_t) );
    ctx->accdb_shfork = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t) );
  }
  ctx->accdb_root_fork = &accdb_shmem_ro->root_fork_id;

  ctx->delta.chain     = (uint const *)( (uchar const *)accdb_shmem_ro + accdb_shmem_ro->delta.chain_off );
  ctx->delta.pool      = (fd_accdb_delta_t const *)( (uchar const *)accdb_shmem_ro + accdb_shmem_ro->delta.ele_off );
  ctx->delta.chain_cnt = accdb_shmem_ro->delta.chain_cnt;
  ctx->delta.chain_idx = 0UL;
  ctx->delta.ele_idx   = UINT_MAX;

  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "replay_snapmk" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
      fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->replay_in_mem      = link_wksp->wksp;
      ctx->replay_in_seq_prod = fd_mcache_seq_laddr_const( link->mcache );
    } else if( 0==strcmp( link->name, "snaprd_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_SNAPRD;
      fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      FD_CHECK_CRIT( link->mtu<=UINT_MAX, "oob MTU" );
      ctx->rd_in_mem = link_wksp->wksp;
      ctx->rd_in_mtu = link->mtu;
      /* fseq used for cnc and flow control of snaprd tile */
      ulong * fseq = tile->in_link_fseq[ i ];
      FD_CHECK_ERR( fseq, "no fseq for snaprd_out link" );
      ctx->rd_fseq = (atomic_ulong *)fseq;
      ctx->rd_ctl  = fd_fseq_app_laddr( fseq );
      FD_STATIC_ASSERT( sizeof(ulong)<=FD_FSEQ_APP_FOOTPRINT, fseq_app_space );
    } else {
      FD_LOG_ERR(( "Unexpected input link \"%s\"", link->name ));
    }
  }
  FD_CHECK_ERR( ctx->replay_in_mem, "missing replay_snapmk link" );
  ctx->replay_in_seq_cons = __atomic_load_n( ctx->replay_in_seq_prod, __ATOMIC_ACQUIRE );
  FD_CHECK_ERR( ctx->rd_in_mem,     "missing snaprd_out link" );

  FD_TEST( tile->out_cnt >= 2 );
  FD_TEST( tile->out_cnt <= FD_TOPO_MAX_TILE_OUT_LINKS );
  ctx->zp_cnt = tile->out_cnt - 1UL;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0!=strcmp( link->name, "snapmk_zp" ) ) {
      FD_LOG_ERR(( "Unexpected output link \"%s\"", link->name ));
    }
    FD_TEST( link->mcache );
    FD_TEST( fd_mcache_depth( link->mcache )==FD_SNAPMK_ZP_DEPTH );
    ctx->zp_out[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->zp_out[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->zp_out[ i ].mem, link->dcache );
    ctx->zp_out[ i ].wmark  = fd_dcache_compact_wmark ( ctx->zp_out[ i ].mem, link->dcache, link->mtu );
    ctx->zp_out[ i ].chunk  = ctx->zp_out[ i ].chunk0;

    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * consumer = &topo->tiles[ j ];
      for( ulong k=0UL; k<consumer->in_cnt; k++ ) {
        if( FD_LIKELY( consumer->in_link_id[ k ]!=tile->out_link_id[ i ] ) ) continue;
        if( FD_UNLIKELY( !consumer->in_link_reliable[ k ] ) ) continue;
        FD_TEST( !ctx->zp_cons_fseq[ i ] );
        ctx->zp_cons_fseq[ i ] = consumer->in_link_fseq[ k ];
      }
    }
    FD_TEST( ctx->zp_cons_fseq[ i ] );
  }

  ctx->out.out_idx = tile->out_cnt - 1UL;
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ ctx->out.out_idx ] ];
  if( 0!=strcmp( out_link->name, "snapmk_out" ) ) {
    FD_LOG_ERR(( "Unexpected output link \"%s\"", out_link->name ));
  }
  FD_CHECK_ERR( out_link->mtu >= sizeof(fd_snapmk_msg_t), "snapmk_out link MTU too small" );
  ctx->out.mem    = fd_wksp_containing( out_link->dcache );
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.mem, out_link->dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.mem, out_link->dcache, out_link->mtu );
  ctx->out.chunk  = ctx->out.chunk0;

  FD_TEST( out_link->mcache );
  ctx->out.seq_prod = fd_mcache_seq_laddr( out_link->mcache );
  ctx->out.cons_cnt = 0UL;
  for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
    fd_topo_tile_t const * consumer = &topo->tiles[ j ];
    for( ulong k=0UL; k<consumer->in_cnt; k++ ) {
      if( FD_LIKELY( consumer->in_link_id[ k ]!=tile->out_link_id[ ctx->out.out_idx ] ) ) continue;
      if( FD_UNLIKELY( !consumer->in_link_reliable[ k ] ) ) continue;
      FD_CHECK_ERR( ctx->out.cons_cnt<SNAPMK_OUT_CONS_MAX, "too many snapmk_out consumers" );
      FD_TEST( consumer->in_link_fseq[ k ] );
      ctx->out.cons_fseq[ ctx->out.cons_cnt++ ] = consumer->in_link_fseq[ k ];
    }
  }

  ctx->zst = ZSTD_initStaticCStream( _zstd, ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL ) );
  FD_TEST( ctx->zst );
  ulong zst_err;
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_BACKUP_ZSTD_LEVEL );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->raw_buf  = (ZSTD_inBuffer ){ .src = ctx->raw,  .size = 0UL         };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = ctx->comp, .size = COMP_BUF_SZ };

  ctx->rd_fseq[0]   = 0UL;
  ctx->rd_seq       = 0UL;
  ctx->rd_seq_cache = ULONG_MAX;
}

/* zip_reset discards any buffered data and assumes that the compression
   stream is clean (last frame was finished). */

static void
zip_reset( fd_snapmk_t * ctx ) {
  ctx->raw_buf.size = 0UL;
  ctx->raw_buf.pos  = 0UL;
}

/* zip_append adds bytes into the input buffer (opens a new frame if
   none is open).  Panics if raw_buf is out of buf space; it is the
   caller's responsibility to guarantee that data_sz is small enough. */

static void
zip_append( fd_snapmk_t * ctx,
            void const *  data,
            ulong         data_sz ) {
  if( FD_UNLIKELY( !data_sz ) ) return;
  FD_CHECK_CRIT( ctx->raw_buf.size + data_sz <= RAW_BUF_SZ, "insufficient raw buffer space" );
  fd_memcpy( ctx->raw + ctx->raw_buf.size, data, data_sz );
  ctx->raw_buf.size += data_sz;
}

/* zip_flush provides the input buffer to the Zstandard compressor.
   Depending on directive, it ...
     (ZSTD_e_continue) ... optimistically does compression work
     (ZSTD_e_flush) ... drains/empties the input buffer without ending
                        the current frame
     (ZSTD_e_end) ... ends the current frame.
   Does not sync the underlying file descriptor. */

static void
zip_flush( fd_snapmk_t *     ctx,
           ZSTD_EndDirective directive ) {

  /* Compress chunk */
  ulong raw_pos = ctx->raw_buf.pos;
  long  t0  = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, directive );
  long  t1  = fd_tickcount();
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2 failed: %s", ZSTD_getErrorName( ret ) ));
  }
  ctx->metrics.bytes_compressed += ctx->raw_buf.pos - raw_pos;
  ctx->metrics.compress_ticks   += (ulong)( t1-t0 );

  /* Move uncompressed bytes to left */
  if( ctx->raw_buf.pos < ctx->raw_buf.size ) {
    memmove( ctx->raw,
             ctx->raw + ctx->raw_buf.pos,
             ctx->raw_buf.size - ctx->raw_buf.pos );
    ctx->raw_buf.size -= ctx->raw_buf.pos;
    ctx->raw_buf.pos   = 0UL;
  } else {
    ctx->raw_buf.size = 0UL;
    ctx->raw_buf.pos  = 0UL;
  }

  /* Write compressed bytes to file */
  ulong comp_wr_;
  ulong comp_sz = ctx->comp_buf.pos;
  t0 = fd_tickcount();
  int wr_err = fd_io_write(
      ctx->snap_fd,
      ctx->comp,
      comp_sz, comp_sz,
      &comp_wr_ );
  t1 = fd_tickcount();
  if( FD_UNLIKELY( wr_err ) ) {
    FD_LOG_ERR(( "fd_io_write failed: %s", fd_io_strerror( wr_err ) ));
  }
  if( FD_UNLIKELY( comp_wr_ != comp_sz ) ) {
    FD_LOG_ERR(( "fd_io_write did not write full buffer (expected %lu bytes, wrote %lu bytes)", comp_sz, comp_wr_ ));
  }
  ctx->metrics.bytes_written    += comp_wr_;
  ctx->metrics.io_blocked_ticks += (ulong)( t1-t0 );
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;
}

/* zip_align aligns the Zstandard compressed stream by 512 bytes using
   skippable frames. */

static void
zip_align( fd_snapmk_t * ctx ) {
  long off = lseek( ctx->snap_fd, 0L, SEEK_CUR );
  if( FD_UNLIKELY( off<0L ) ) {
    FD_LOG_ERR(( "lseek failed: %i-%s", errno, fd_io_strerror( errno ) ));
  }
  ulong uoff   = (ulong)off;
  /* Align using skippable frame */
  ulong aoff   = fd_ulong_align_up( uoff, 4096UL );
  ulong pad_sz = aoff - uoff;
  if( FD_UNLIKELY( pad_sz>0UL && pad_sz<8UL ) ) {
    aoff   += 4096UL;
    pad_sz += 4096UL;
  }
  if( pad_sz>0UL ) {
    long t0 = fd_tickcount();
    uchar frame_hdr[ 8 ];
    FD_STORE( uint, frame_hdr,   ZSTD_MAGIC_SKIPPABLE_START );
    FD_STORE( uint, frame_hdr+4, (uint)( pad_sz-8 ) );
    ulong wr_sz_;
    int err = fd_io_write( ctx->snap_fd, frame_hdr, 8UL, 8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
    static uchar const zero[ 4096UL ] = {0};
    err = fd_io_write( ctx->snap_fd, zero, pad_sz-8UL, pad_sz-8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
    long t1 = fd_tickcount();
    ctx->metrics.bytes_written    += pad_sz;
    ctx->metrics.io_blocked_ticks += (ulong)( t1-t0 );
  }
  atomic_store_explicit( ctx->file_off_p, aoff, memory_order_release );
}

/* snapmk_status_cache_prepare writes the file header for the serialized
   status cache. */

static void
snapmk_status_cache_prepare( fd_snapmk_t * ctx ) {
  ulong slot = ctx->bank->f.slot;
  fd_txncache_writer_init( ctx->txncache_writer, ctx->txncache, slot );
  ulong bin_sz = fd_txncache_writer_serialized_sz( ctx->txncache, slot );

  zip_reset( ctx );
  fd_tar_meta_t meta;
  fd_backup_tar_file_hdr( &meta, bin_sz );
  fd_cstr_ncpy( meta.name, "snapshots/status_cache", sizeof(meta.name) );
  fd_tar_meta_set_chksum( &meta );
  ctx->status_cache_pad = fd_ulong_align_up( bin_sz, sizeof(fd_tar_meta_t) ) - bin_sz;
  zip_append( ctx, &meta, sizeof(fd_tar_meta_t) );
  zip_flush( ctx, ZSTD_e_continue ); /* still need padding in current frame */
}

/* snapmk_status_cache does a unit of status cache serialization and
   compression work.  Returns 0 once status cache compression is fully
   done (TAR/Zstandard out stream clean).  Otherwise, returns 1, which
   implies another work call is needed. */

static int
snapmk_status_cache( fd_snapmk_t * ctx ) {
  if( FD_UNLIKELY( ctx->raw_buf.size + FD_TXNCACHE_WRITER_BUF_MIN > RAW_BUF_SZ ) ) {
    zip_flush( ctx, ZSTD_e_continue );
    return 1;
  }
  ulong buf_rem  = RAW_BUF_SZ - ctx->raw_buf.size;
  ulong chunk_sz = fd_txncache_writer_serialize(
      ctx->txncache_writer,
      ctx->raw + ctx->raw_buf.size,
      buf_rem );
  ctx->raw_buf.size += chunk_sz;
  if( FD_UNLIKELY( !chunk_sz ) ) { /* done serializing? */
    zip_flush( ctx, ZSTD_e_continue );
    if( ctx->status_cache_pad ) {
      FD_CHECK_CRIT( ctx->status_cache_pad<sizeof(fd_tar_meta_t), "invalid status_cache_pad" );
      static uchar const zero[ sizeof(fd_tar_meta_t) ] = {0};
      zip_append( ctx, zero, ctx->status_cache_pad );
    }
    zip_flush( ctx, ZSTD_e_end );
    ctx->state = SNAPMK_STATE_EOF_MARKER;
    return 0;
  }
  return 1;
}

/* snapmk_eof_marker writes a compressed "end of TAR stream" marker.
   Assumes clean tar and Zstandard stream. */

static void
snapmk_eof_marker( fd_snapmk_t * ctx ) {
  FD_CHECK_ERR( ctx->raw_buf.size==0UL, "Zstandard stream unclean" );
  ctx->raw_buf.pos  =    0UL;
  ctx->raw_buf.size = 1024UL;
  fd_memset( ctx->raw, 0, 1024UL );
  zip_flush( ctx, ZSTD_e_end );
}

/* snapmk_done_rename renames the "partial" snapshot file to a proper
   "snapshot-*.tar.zst" or "incremental-snapshot-*-*.tar.zst" file. */

static void
snapmk_done_rename( fd_snapmk_t * ctx ) {
  long file_sz = lseek( ctx->snap_fd, 0L, SEEK_END );
  if( FD_UNLIKELY( file_sz<0L ) ) {
    FD_LOG_ERR(( "lseek failed: %s", fd_io_strerror( errno ) ));
  }
  ctx->final_sz = (ulong)file_sz;

  fd_backup_inode_t * inode = &ctx->pool[ ctx->snap_idx ];
  struct flock lock = {
    .l_type   = F_UNLCK,
    .l_whence = SEEK_SET
  };
  if( FD_UNLIKELY( fcntl( ctx->snap_fd, F_SETLK, &lock ) ) ) {
    FD_LOG_ERR(( "fcntl(F_UNLCK, %s) failed: %i-%s",
                 inode->name, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( renameat( ctx->snap_dir_fd, inode->name, ctx->snap_dir_fd, ctx->final_name ) ) ) {
    FD_LOG_ERR(( "renameat(%s, %s) failed: %s", inode->name, ctx->final_name, fd_io_strerror( errno ) ));
  }
  fd_cstr_ncpy( inode->name, ctx->final_name, sizeof(inode->name) );

  if( FD_UNLIKELY( ctx->incremental ) ) {
    inode->full_slot = ctx->base_slot;
    inode->incr_slot = ctx->bank->f.slot;
    ctx->metrics.last_snapshot_slot_finished_incremental = ctx->bank->f.slot;
  } else {
    inode->full_slot = ctx->bank->f.slot;
    inode->incr_slot = ULONG_MAX;
    ctx->base_slot   = ctx->bank->f.slot;
    ctx->metrics.last_snapshot_slot_finished_full = ctx->bank->f.slot;
  }

  ctx->snap_fd = -1;

  FD_LOG_INFO(( "%s snapshot created in %.3f seconds (%s/%s, %.3f GB)",
                ctx->incremental ? "incremental" : "full",
                (double)( fd_log_wallclock() - ctx->start_time )/1e9,
                ctx->snap_dir, ctx->final_name,
                (double)file_sz/1e9 ));

  ctx->state = SNAPMK_STATE_DONE;
}

/* snapshot_sync_advance requests replay to advance the snapshot sync
   state machine. */

static void
snapshot_sync_transition( fd_snapmk_t * ctx,
                          ulong         state_from,
                          ulong         state_req,
                          ulong         state_to ) {
  while( FD_UNLIKELY( fd_accdb_snapshot_sync_state( ctx->accdb_snapshot_sync )!=state_from ) ) FD_YIELD();
  fd_accdb_snapshot_sync_advance( ctx->accdb_snapshot_sync, state_req );
  while( FD_UNLIKELY( fd_accdb_snapshot_sync_state( ctx->accdb_snapshot_sync )!=state_to ) ) FD_YIELD();
}

static ulong
snapshot_sync_request( fd_snapmk_t * ctx,
                       ulong         state_from,
                       ulong         state_req ) {
  while( FD_UNLIKELY( fd_accdb_snapshot_sync_state( ctx->accdb_snapshot_sync )!=state_from ) ) FD_YIELD();
  fd_accdb_snapshot_sync_advance( ctx->accdb_snapshot_sync, state_req );
  for(;;) {
    ulong state = fd_accdb_snapshot_sync_state( ctx->accdb_snapshot_sync );
    if( FD_LIKELY( state!=state_req ) ) return state;
    FD_YIELD();
  }
}

static inline ulong
zp_publish( fd_snapmk_t *       ctx,
            fd_stem_context_t * stem,
            ulong               out_idx,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               ctl,
            ulong               tsorig,
            ulong               tspub ) {
  FD_TEST( out_idx<ctx->zp_cnt );
  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong            depth  = stem->depths [ out_idx ];
  ulong *          seqp   = &stem->seqs  [ out_idx ];
  ulong            seq    = *seqp;
# if FD_HAS_AVX
  fd_mcache_publish_avx( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# elif FD_HAS_ARM
  fd_mcache_publish_arm( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# else
  fd_mcache_publish    ( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
# endif
  ulong cr_avail = fd_ulong_sat_sub( stem->cr_avail[ out_idx ], 1UL );
  stem->cr_avail[ out_idx ] = cr_avail;
  *stem->min_cr_avail       = fd_ulong_min( cr_avail, *stem->min_cr_avail );
  if( FD_UNLIKELY( !cr_avail ) ) ctx->zp_ready &= ~fd_ulong_mask_bit( (int)out_idx );
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

/* broadcast is called repeatedly until a message has been sent to all
   snapzp tiles.  Returns 1 if the message was sent to all tiles, 0
   otherwise (call again).

   broadcast_prepare must be called once before attempting to broadcast.

   Typically, a barrier is installed before the broadcast (wait for all
   snapzp tiles to catch up before broadcasting).  Then, another
   barrier is installed at the broadcast (wait for all snapzp tiles to
   ACK the broadcast before continuing). */

static void
broadcast_prepare( fd_snapmk_t * ctx ) {
  ctx->zp_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
}

static int
broadcast( fd_snapmk_t *       ctx,
           fd_stem_context_t * stem,
           ulong               ctl,
           int *               charge_busy ) {
  int did_work = 0;
  ulong zp_cnt = ctx->zp_cnt;
  for( ulong i=0UL; i<zp_cnt; i++ ) {
    if( !fd_ulong_extract_bit( ctx->zp_flush_pending, (int)i ) ) continue;
    if( !stem->cr_avail[ i ] ) continue;
    zp_publish( ctx, stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    ctx->zp_barrier[ i ] = stem->seqs[ i ]; /* FINISH barrier */
    ctx->zp_flush_pending &= ~fd_ulong_mask_bit( (int)i );
    *charge_busy = 1;
    did_work = 1;
  }
  if( (!ctx->zp_flush_pending) & (!did_work) ) {
    return 1;
  }
  return 0;
}

/* barrier_install blocks this tile until all snapzp tiles have caught
   up with the last published messages. */

static void
barrier_install( fd_snapmk_t *             ctx,
                 fd_stem_context_t const * stem ) {
  ulong zp_cnt = ctx->zp_cnt;
  for( ulong i=0UL; i<zp_cnt; i++ ) {
    ctx->zp_barrier[ i ] = stem->seqs[ i ]; /* FLUSH barrier */
  }
}

/* zp_rr_next picks a snapzp tile for a new job (ULONG_MAX if none are
   ready).  FIXME rewrite this O(1) with rotate+find_lsb. */

static ulong
zp_rr_next( fd_snapmk_t * ctx ) {
  ulong n = ctx->zp_cnt;
  for( ulong k=0UL; k<n; k++ ) {
    ulong idx = ctx->zp_rr_idx;
    ctx->zp_rr_idx = fd_ulong_if( ctx->zp_rr_idx+1UL>=n, 0UL, ctx->zp_rr_idx+1UL );
    if( ctx->zp_ready & (1UL<<idx) ) return idx;
  }
  return ULONG_MAX;
}

/* zp_alloc allocates a message payload on snapzp_mk[ out_idx ]. */

static inline void *
zp_alloc( fd_snapmk_t * ctx,
          ulong         out_idx,
          ulong         sz,
          ulong *       chunk ) {
  FD_TEST( sz );
  FD_TEST( out_idx<ctx->zp_cnt );
  *chunk = ctx->zp_out[ out_idx ].chunk;
  void * laddr = fd_chunk_to_laddr( ctx->zp_out[ out_idx ].mem, *chunk );
  ctx->zp_out[ out_idx ].chunk =
      fd_dcache_compact_next( *chunk, sz, ctx->zp_out[ out_idx ].chunk0, ctx->zp_out[ out_idx ].wmark );
  return laddr;
}

/* rd_ack sends read acknowledgements to snaprd. */

static void
rd_ack( fd_snapmk_t *             ctx,
        fd_stem_context_t const * stem ) {
  ulong zp_cnt = ctx->zp_cnt;
  ulong rd_seq = ctx->rd_seq;
  for( ulong i=0UL; i<zp_cnt; i++ ) {
    /* Must be the live fseq, not stem's cached cons_seq.  Publishes are
       gated on the live consumer position (zp_sync_cr_avail), so pub can
       outrun stem's cached cons_seq by more than the link depth.  Indexing
       rd_shadow with a stale cons would then read a slot that a newer
       publish has already wrapped onto, yielding a floor that is too new
       and releasing snaprd buffers that snapzp is still reading. */
    ulong cons = fd_fseq_query( ctx->zp_cons_fseq[ i ] );
    ulong pub  = stem->seqs[ i ];
    if( FD_UNLIKELY( !fd_seq_lt( cons, pub ) ) ) continue;
    /* snapzp ack for 'cons' means that this snapzp has fully consumed
       up to snaprd seq 'floor'. */
    ulong floor = ctx->rd_shadow[ i ][ cons & (FD_SNAPMK_ZP_DEPTH-1) ];
    rd_seq = fd_seq_lt( floor, rd_seq ) ? floor : rd_seq;
  }
  if( rd_seq != ctx->rd_seq_cache ) {
    ctx->rd_seq_cache = rd_seq;
    atomic_store_explicit( ctx->rd_fseq, rd_seq, memory_order_release );
  }
}

/* recv_credit is called whenever consumer flow control credits are
   refreshed. */

static void
recv_credit( fd_snapmk_t * ctx,
             ulong         out_idx,
             ulong         out_seq,
             ulong         cons_seq ) {
  if( out_idx < ctx->zp_cnt ) {
    long in_flight = fd_long_max( fd_seq_diff( out_seq, cons_seq ), 0L );
    long cr_avail  = FD_SNAPMK_ZP_DEPTH - in_flight;
    ctx->zp_ready |= fd_ulong_if( cr_avail>0L, 1UL<<out_idx, 0UL );
  }
}

/* zp_sync_cr_avail syncs zp_ready and stem credit accounting. */

static void
zp_sync_cr_avail( fd_snapmk_t *             ctx,
                  fd_stem_context_t const * stem ) {
  ulong zp_cnt = ctx->zp_cnt;
  for( ulong i=0UL; i<zp_cnt; i++ ) {
    if( FD_LIKELY( stem->cr_avail[ i ] ) ) continue; /* stem already agrees */
    if( FD_LIKELY( !fd_ulong_extract_bit( ctx->zp_ready, (int)i ) ) ) continue;
    ulong cons      = fd_fseq_query( ctx->zp_cons_fseq[ i ] );
    long  in_flight = fd_long_max( fd_seq_diff( stem->seqs[ i ], cons ), 0L );
    ulong cr_avail  = (ulong)fd_long_max( (long)FD_SNAPMK_ZP_DEPTH-in_flight, 0L );
    stem->cr_avail[ i ] = cr_avail;
    if( FD_UNLIKELY( !cr_avail ) ) ctx->zp_ready &= ~fd_ulong_mask_bit( (int)i );
  }
}

/* check_credit runs every run loop iteration.  It specifies custom flow
   control behavior. */

static void
check_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               charge_busy,
              int *               is_backpressured ) {
  (void)stem; (void)charge_busy; (void)is_backpressured;

  if( FD_LIKELY( ctx->state!=SNAPMK_STATE_IDLE &&
                 ctx->state!=SNAPMK_STATE_SLEEP ) ) {
    zp_sync_cr_avail( ctx, stem );
  }

  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
  case SNAPMK_STATE_SLEEP:
    break;

  /* these state send jobs to snapzp tiles */
  case SNAPMK_STATE_ACCDB_DISK:
    rd_ack( ctx, stem );
    if( FD_UNLIKELY( ctx->disk_out_idx>=0 ) ) {
      if( FD_UNLIKELY( !fd_ulong_extract_bit( ctx->zp_ready, ctx->disk_out_idx ) ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    __attribute__((fallthrough));
  case SNAPMK_STATE_START:
  case SNAPMK_STATE_ACCDB_CACHE:
  case SNAPMK_STATE_ACCDB_DELTA:
    if( FD_UNLIKELY( !ctx->zp_ready ) ) {
      *is_backpressured = 1;
      return;
    }
    *is_backpressured = 0; /* undo stem backpressure */
    break;

  /* these states broadcast */
  case SNAPMK_STATE_ACCDB_CACHE_FLUSH:
  case SNAPMK_STATE_ACCDB_CACHE_FINISH:
  case SNAPMK_STATE_ACCDB_DISK_FLUSH:
  case SNAPMK_STATE_ACCDB_DISK_FINISH:
  case SNAPMK_STATE_ACCDB_DELTA_FLUSH:
  case SNAPMK_STATE_ACCDB_DELTA_FINISH: {
    /* wait for snapzp tiles to acknowledge zp_barrier[*] */
    *is_backpressured = 0;
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( FD_UNLIKELY( fd_seq_lt( fd_fseq_query( ctx->zp_cons_fseq[ i ] ), ctx->zp_barrier[ i ] ) ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    break;
  }
  default:
    /* use default backpressure mechanism */
    break;
  }
}

/* snapmk_tar_headers writes out the first few fixed parts of a snapshot
   file. */

static void
snapmk_tar_headers( fd_snapmk_t * ctx ) {
  ulong slot = ctx->bank->f.slot;

  ctx->raw_buf.pos = ctx->raw_buf.size = 0UL;
  uchar * p = ctx->raw;
  fd_tar_meta_t meta;

  fd_backup_tar_file_hdr( &meta, 5UL );
  fd_cstr_ncpy( meta.name, "version", sizeof(meta.name) );
  fd_tar_meta_set_chksum( &meta );
  memcpy( p, &meta, sizeof(fd_tar_meta_t) );
  p += sizeof(fd_tar_meta_t);

  memcpy( p,   "1.2.0",       5UL );
  memset( p+5, 0,       512UL-5UL );
  p += 512UL;

  fd_backup_tar_dir_hdr( &meta );
  fd_cstr_ncpy( meta.name, "snapshots/", sizeof(meta.name) );
  fd_tar_meta_set_chksum( &meta );
  memcpy( p, &meta, sizeof(fd_tar_meta_t) );
  p += sizeof(fd_tar_meta_t);

  fd_backup_tar_dir_hdr( &meta );
  fd_cstr_printf_check( meta.name, sizeof(meta.name), NULL, "snapshots/%lu/", slot );
  fd_tar_meta_set_chksum( &meta );
  memcpy( p, &meta, sizeof(fd_tar_meta_t) );
  p += sizeof(fd_tar_meta_t);

  ulong manifest_sz = fd_snap_manifest_serialized_sz( ctx->bank );
  fd_backup_tar_file_hdr( &meta, manifest_sz );
  fd_cstr_printf_check( meta.name, sizeof(meta.name), NULL, "snapshots/%lu/%lu", slot, slot );
  fd_tar_meta_set_chksum( &meta );
  memcpy( p, &meta, sizeof(fd_tar_meta_t) );
  p += sizeof(fd_tar_meta_t);
  ctx->raw_buf.size = (ulong)( p - ctx->raw );
  ctx->manifest_pad = fd_ulong_align_up( manifest_sz, 512UL ) - manifest_sz;

  zip_flush( ctx, ZSTD_e_end );
}

/* snapmk_manifest_chunk writes out a chunk of snapshot manifest data.
   Returns 1 if there is more work to do, 0 if the snapshot manifest was
   fully written. */

static int
snapmk_manifest_chunk( fd_snapmk_t * ctx ) {
  if( FD_UNLIKELY( ctx->raw_buf.size + FD_SSMANIFEST_BUF_MIN > RAW_BUF_SZ ) ) {
    zip_flush( ctx, ZSTD_e_continue );
    return 1;
  }
  ulong buf_rem = RAW_BUF_SZ - ctx->raw_buf.size;
  ulong chunk_sz = fd_snap_manifest_serialize(
      ctx->manifest_writer,
      ctx->raw + ctx->raw_buf.size,
      buf_rem );
  ctx->raw_buf.size += chunk_sz;
  if( FD_LIKELY( chunk_sz ) ) return 1;

  /* Done compressing manifest */
  zip_flush( ctx, ZSTD_e_continue );
  if( ctx->manifest_pad ) {
    fd_memset( ctx->raw, 0, ctx->manifest_pad );
    ctx->raw_buf.size = ctx->manifest_pad;
  }
  zip_flush( ctx, ZSTD_e_end );
  zip_align( ctx );
  return 0;
}

/* snapmk_accdb_cache schedules accdb cache work.  Returns 1 if there is
   more work to do, 0 otherwise. */

static int
snapmk_accdb_cache( fd_snapmk_t *       ctx,
                    fd_stem_context_t * stem ) {
  ulong out_idx = zp_rr_next( ctx );
  fd_backup_cache_msg_t * frag = ctx->scan_batch;
  frag = fd_backup_cache_scan( ctx->acc_cache, frag );
  if( FD_UNLIKELY( !frag ) ) return 0;

  /* remove duplicates
     first pass (fast), ILP-friendly/vectorizable check */
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    uint acc_idx = frag->acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;
    if( FD_UNLIKELY( fd_backup_visited_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
      frag->acc_idx[ i ] = UINT_MAX;
    }
  }

  /* second pass: intra-batch conflict detect */
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    uint acc_idx = frag->acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;
    if( FD_UNLIKELY( fd_backup_visited_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
      frag->acc_idx[ i ] = UINT_MAX;
      memset( frag->pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
      continue;
    }
    fd_backup_visited_insert( ctx->visited_set, (ulong)acc_idx );
  }

  /* publish a batch of cached accounts */
  ulong chunk;
  void * payload = zp_alloc( ctx, (ulong)out_idx, sizeof(fd_backup_cache_msg_t), &chunk );
  fd_memcpy( payload, frag, sizeof(fd_backup_cache_msg_t) );
  ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_CACHE, 0, 0, 0 );
  zp_publish( ctx, stem, (ulong)out_idx, 0UL, chunk, sizeof(fd_backup_cache_msg_t), ctl, 0UL, 0UL );

  return 1;
}

/* snapmk_accdb_delta drains a batch of incremental snapshot accounts
   and passes them to snapzp for a compression job. */

static int
snapmk_accdb_delta( fd_snapmk_t *       ctx,
                    fd_stem_context_t * stem ) {
  ulong out_idx = zp_rr_next( ctx );

  fd_backup_delta_msg_t batch = {0};
  while( batch.cnt<FD_BACKUP_CACHE_PARA ) {
    if( FD_UNLIKELY( ctx->delta.ele_idx==UINT_MAX ) ) {
      if( FD_UNLIKELY( ctx->delta.chain_idx>=ctx->delta.chain_cnt ) ) break;
      ctx->delta.ele_idx = __atomic_load_n( &ctx->delta.chain[ ctx->delta.chain_idx++ ], __ATOMIC_ACQUIRE );
      continue;
    }
    fd_accdb_delta_t const * cur = &ctx->delta.pool[ ctx->delta.ele_idx ];
    ctx->delta.ele_idx = __atomic_load_n( &cur->next, __ATOMIC_RELAXED );
    fd_memcpy( &batch.pubkey[ batch.cnt ], cur->pubkey, sizeof(fd_pubkey_t) );
    batch.cnt++;
  }
  if( FD_UNLIKELY( !batch.cnt ) ) return 0;

  ulong chunk;
  void * payload = zp_alloc( ctx, out_idx, sizeof(fd_backup_delta_msg_t), &chunk );
  fd_memcpy( payload, &batch, sizeof(fd_backup_delta_msg_t) );
  ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DELTA, 0, 0, 0 );
  zp_publish( ctx, stem, out_idx, 0UL, chunk, sizeof(fd_backup_delta_msg_t), ctl, 0UL, 0UL );

  return 1;
}

/* snapmk_replay_sleep sleeps until the replay tile publishes a new
   snapshot command or IDLE_SLEEP nanoseconds pass. */

static void
snapmk_replay_sleep( fd_snapmk_t * ctx ) {
  struct timespec const ts = { .tv_sec = (IDLE_SLEEP)/(long)1e9, .tv_nsec = (IDLE_SLEEP)%(long)1e9 };
  long res = syscall( SYS_futex, (uint *)ctx->replay_in_seq_prod, FUTEX_WAIT, (uint)ctx->replay_in_seq_cons, &ts );
  if( res==0 || (res==-1 && errno==EAGAIN) ) {
    /* stop sleeping */
    ctx->state     = SNAPMK_STATE_IDLE;
    ctx->idle_iter = 0UL;
  } else if( res==-1 && errno!=ETIMEDOUT ) {
    FD_LOG_ERR(( "FUTEX_WAIT failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

/* snapmk_msg_alloc allocates space for a snapmk_out payload. */

static fd_snapmk_msg_t *
snapmk_msg_alloc( fd_snapmk_t * ctx ) {
  return fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
}

/* wake all reliable consumers by unconditionally waking them (snapsv
   tiles).  This is inefficient (does a FUTEX_WAKE syscall), but
   acceptable given the very low frag production rate.  */

static void
snapmk_out_wake( fd_snapmk_t *       ctx,
                 fd_stem_context_t * stem ) {
  fd_mcache_seq_update( ctx->out.seq_prod, stem->seqs[ ctx->out.out_idx ] );
  if( FD_UNLIKELY( -1==syscall( SYS_futex, (uint *)ctx->out.seq_prod, FUTEX_WAKE, INT_MAX, NULL, NULL, 0 ) ) ) {
    FD_LOG_ERR(( "FUTEX_WAKE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

/* snapmk_msg_publish publishes a msg and frag on snapmk_out. */

static void
snapmk_msg_publish( fd_snapmk_t *       ctx,
                    fd_stem_context_t * stem,
                    ulong               msg_type ) {
  ulong sz;
  switch( msg_type ) { /* known at compile time */
  case FD_SNAPMK_MSG_CREATED: sz = sizeof(fd_snapmk_msg_created_t); break;
  case FD_SNAPMK_MSG_DELETED: sz = sizeof(fd_snapmk_msg_deleted_t); break;
  case FD_SNAPMK_MSG_STARTED: sz = sizeof(fd_snapmk_msg_started_t); break;
  case FD_SNAPMK_MSG_FAILED:  sz = sizeof(fd_snapmk_msg_failed_t);  break;
  case FD_SNAPMK_MSG_FOUND:   sz = sizeof(fd_snapmk_msg_found_t);   break;
  default:
    FD_LOG_CRIT(( "invalid msg_type %lu", msg_type ));
  }
  ulong chunk = ctx->out.chunk;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->out.out_idx, msg_type, chunk, sz, 0UL, 0UL, tspub );
  ctx->out.chunk = fd_dcache_compact_next( chunk, sz, ctx->out.chunk0, ctx->out.wmark );
  snapmk_out_wake( ctx, stem );
}

/* after_credit runs every run loop iteration, provided that all out
   links have at least STEM_BURST credit available, or check_credit
   passed. */

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;

  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    if( FD_UNLIKELY( ++ctx->idle_iter >= IDLE_THRES ) ) {
      ctx->state     = SNAPMK_STATE_SLEEP;
      ctx->idle_iter = 0UL;
    }
    *charge_busy = 0;
    break;
  case SNAPMK_STATE_SLEEP: {
    snapmk_replay_sleep( ctx );
    *charge_busy = 0;
    break;
  }
  case SNAPMK_STATE_START: {
    ulong zp_cnt   = ctx->zp_cnt;
    int   did_work = 0;
    for( ulong i=0UL; i<zp_cnt; i++ ) {
      /* FIXME use find_lsb? */
      if( !fd_ulong_extract_bit( ctx->zp_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong chunk;
      fd_backup_start_msg_t * frag = zp_alloc( ctx, i, sizeof(fd_backup_start_msg_t), &chunk );
      memset( frag, 0, sizeof(fd_backup_start_msg_t) );
      frag->slot     = ctx->bank->f.slot;
      frag->snap_idx = ctx->snap_idx;
      frag->fork_id  = ctx->bank->accdb_fork_id.val;
      ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_START, 0, 0, 0 );
      zp_publish( ctx, stem, i, 0UL, chunk, sizeof(fd_backup_start_msg_t), ctl, 0UL, 0UL );
      ctx->zp_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      ctx->zp_ready         &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
      did_work = 1;
    }
    /* all snapzp tiles have been told to start; begin writing the tar */
    if( (!ctx->zp_flush_pending) & (!did_work) ) {
      ctx->state = SNAPMK_STATE_TAR_HEADERS;
    }
    break;
  }
  case SNAPMK_STATE_TAR_HEADERS:
    *charge_busy = 1;
    snapmk_tar_headers( ctx );
    ctx->state = SNAPMK_STATE_MANIFEST;
    break;
  case SNAPMK_STATE_MANIFEST:
    *charge_busy = 1;
    if( FD_UNLIKELY( !snapmk_manifest_chunk( ctx ) ) ) {
      ctx->state = ctx->incremental ? SNAPMK_STATE_ACCDB_DELTA : SNAPMK_STATE_ACCDB_CACHE;
    }
    break;
  case SNAPMK_STATE_ACCDB_CACHE: {
    *charge_busy = 1;
    if( FD_UNLIKELY( !snapmk_accdb_cache( ctx, stem ) ) ) {
      barrier_install( ctx, stem );
      broadcast_prepare( ctx );
      ctx->state = SNAPMK_STATE_ACCDB_CACHE_FLUSH;
    }
    break;
  }
  case SNAPMK_STATE_ACCDB_CACHE_FLUSH: {
    /* done reading from cache; now tell snapzp workers to end their
       Zstandard frames */
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_FLUSH, 0, 0, 0 );
    if( broadcast( ctx, stem, ctl, charge_busy ) ) {
      ctx->state = SNAPMK_STATE_ACCDB_CACHE_FINISH;
    }
    break;
  }
  case SNAPMK_STATE_ACCDB_CACHE_FINISH:
    *charge_busy = 1;
    /* done snapshotting accdb cache;
       now instruct snaprd tile to start reading accdb disk data */
    ctx->state = SNAPMK_STATE_ACCDB_DISK;
    atomic_fetch_add_explicit( ctx->rd_ctl, 1UL, memory_order_release );
    break;
  case SNAPMK_STATE_ACCDB_DISK:
    /* driven by returnable_frag */
    break;
  case SNAPMK_STATE_ACCDB_DISK_FLUSH: {
    /* done reading from disk; now tell snapzp workers to end their
       Zstandard frames */
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_FLUSH, 0, 0, 0 );
    if( broadcast( ctx, stem, ctl, charge_busy ) ) {
      ctx->state = SNAPMK_STATE_ACCDB_DISK_FINISH;
    }
    break;
  }
  case SNAPMK_STATE_ACCDB_DELTA: {
    *charge_busy = 1;
    if( FD_UNLIKELY( !snapmk_accdb_delta( ctx, stem ) ) ) {
      barrier_install( ctx, stem );
      broadcast_prepare( ctx );
      ctx->state = SNAPMK_STATE_ACCDB_DELTA_FLUSH;
    }
    break;
  }
  case SNAPMK_STATE_ACCDB_DELTA_FLUSH: {
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_FLUSH, 0, 0, 0 );
    if( broadcast( ctx, stem, ctl, charge_busy ) ) {
      ctx->state = SNAPMK_STATE_ACCDB_DELTA_FINISH;
    }
    break;
  }
  case SNAPMK_STATE_ACCDB_DISK_FINISH:
  case SNAPMK_STATE_ACCDB_DELTA_FINISH:
    /* accounts done, snapzp workers idle; now process status cache */
    if( FD_UNLIKELY( lseek( ctx->snap_fd, 0L, SEEK_END )<0L ) ) {
      FD_LOG_ERR(( "lseek failed: %i-%s", errno, fd_io_strerror( errno ) ));
    }
    snapmk_status_cache_prepare( ctx );
    ctx->state = SNAPMK_STATE_STATUS_CACHE;
    break;
  case SNAPMK_STATE_STATUS_CACHE:
    /* process status cache piece wise */
    *charge_busy = 1;
    if( FD_UNLIKELY( !snapmk_status_cache( ctx ) ) ) {
      ctx->state = SNAPMK_STATE_EOF_MARKER;
    }
    break;
  case SNAPMK_STATE_EOF_MARKER:
    /* all data written to snapshot, file not yet structurally clean;
       now write end-of-snapshot marker */
    *charge_busy = 1;
    snapmk_eof_marker ( ctx );
    snapmk_done_rename( ctx );
    broadcast_prepare ( ctx );
    ctx->state = SNAPMK_STATE_DONE;
    break;
  case SNAPMK_STATE_DONE: {
    /* snapshot file complete; now broadcast "done" signal to all worker
       tiles, and notify accdb/replay to resume */
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DONE, 0, 1, 0 );
    if( broadcast( ctx, stem, ctl, charge_busy ) ) {
      snapshot_sync_transition( ctx, FD_ACCDB_SNAPSHOT_SYNC_RUNNING, FD_ACCDB_SNAPSHOT_SYNC_DONE, FD_ACCDB_SNAPSHOT_SYNC_IDLE );
      fd_snapmk_msg_created_t * msg = &snapmk_msg_alloc( ctx )->created;
      *msg = (fd_snapmk_msg_created_t) {
        .slot      = ctx->bank->f.slot,
        .base_slot = ctx->incremental ? ctx->base_slot : ULONG_MAX,
        .sz        = ctx->final_sz,
        .pool_idx  = ctx->snap_idx
      };
      fd_cstr_ncpy( msg->name, ctx->final_name, sizeof(msg->name) );
      snapmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_CREATED );
      ctx->state = SNAPMK_STATE_SLEEP;
      ctx->snap_idx = UINT_MAX;
    }
    break;
  }
  case SNAPMK_STATE_FAIL: {
    snapmk_msg_alloc( ctx )->failed = (fd_snapmk_msg_failed_t) {
      .slot      = ctx->bank->f.slot,
      .base_slot = ctx->base_slot
    };
    snapmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_FAILED );
    ctx->snap_idx = UINT_MAX;
    ctx->state    = SNAPMK_STATE_SLEEP;
    *charge_busy  = 1;
    break;
  }
  case SNAPMK_STATE_STARTUP: /* wait for startup */
    if( FD_UNLIKELY( fd_startup_gate_idle( ctx->startup_gate ) ) ) {
      ctx->state = SNAPMK_STATE_STARTUP_BURST;
      fd_snap_pool_recover( ctx->snap_dir_fd, ctx->snap_dir, ctx->pool, ctx->snap_max );
    }
    break;
  case SNAPMK_STATE_STARTUP_BURST: { /* burst publish pre-existing snaps */
    if( FD_UNLIKELY( ctx->startup_pool_idx >= ctx->snap_max ) ) {
      ctx->state = SNAPMK_STATE_SLEEP;
      break;
    }
    ulong snap_idx = ctx->startup_pool_idx++;
    fd_backup_inode_t * inode = &ctx->pool[ snap_idx ];
    if( FD_UNLIKELY( inode->full_slot==ULONG_MAX ) ) break;
    fd_snapmk_msg_found_t * msg = &snapmk_msg_alloc( ctx )->found;
    *msg = (fd_snapmk_msg_found_t) {
      .slot         = inode->incr_slot!=ULONG_MAX ? inode->incr_slot : inode->full_slot,
      .base_slot    = inode->incr_slot!=ULONG_MAX ? inode->full_slot : ULONG_MAX,
      .pool_idx     = (uint)snap_idx,
      .fs_timestamp = LONG_MAX
    };
    fd_cstr_ncpy( msg->name, inode->name, sizeof(msg->name) );
    struct stat st;
    if( FD_UNLIKELY( 0!=fstat( FD_SNAP_FD( snap_idx ), &st ) ) ) break;
    msg->sz           = (ulong)st.st_size;
    msg->fs_timestamp = ((long)st.st_mtim.tv_sec*(long)1e9) + (long)st.st_mtim.tv_nsec;
    snapmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_FOUND );
    break;
  }
  default:
    FD_LOG_CRIT(( "invalid state %u", ctx->state ));
  }
}

/* snap_pool_select finds a free snapshot file descriptor for
   production. */

static uint
snap_pool_select( fd_snapmk_t * ctx ) {

  uint slot0 = ctx->incremental ? ctx->snap_full_max : 0U;
  uint slot1 = ctx->incremental ? ctx->snap_max      : ctx->snap_full_max;
  FD_CHECK_ERR( slot0<slot1, "no snapshot file descriptors reserved" );

  /* if this snapshot already exists, recreate it */
  for( uint i=slot0; i<slot1; i++ ) {
    if( FD_UNLIKELY( !strcmp( ctx->pool[ i ].name, ctx->final_name ) ) ) return i;
  }

  uint  slot_idx = UINT_MAX;
  ulong oldest   = ULONG_MAX;
  for( uint i=slot0; i<slot1; i++ ) {
    if( FD_UNLIKELY( ctx->pool[ i ].full_slot==ULONG_MAX ) ) return i; /* free */
    ulong slot = ctx->incremental ? ctx->pool[ i ].incr_slot : ctx->pool[ i ].full_slot;
    if( slot<oldest ) {
      oldest   = slot;
      slot_idx = i;
    }
  }
  FD_CHECK_ERR( slot_idx!=UINT_MAX, "no snapshot file descriptor to recycle" );

  return slot_idx;
}

/* snap_pool_acquire picks a new file descriptor to hold a snapshot
   file.  May recycle an existing snapshot. */

static uint
snap_pool_acquire( fd_snapmk_t *       ctx,
                   fd_stem_context_t * stem ) {
  uint snap_pool_idx = snap_pool_select( ctx );

  if( FD_UNLIKELY( ctx->pool[ snap_pool_idx ].full_slot==ULONG_MAX ) ) return snap_pool_idx; /* free */

  /* recycle (signals consumers to unlock) */

  FD_CHECK_ERR( snap_pool_idx < ctx->snap_max, "invalid snap_pool_idx" );

  fd_backup_inode_t * inode = &ctx->pool[ snap_pool_idx ];
  fd_snapmk_msg_deleted_t * msg = &snapmk_msg_alloc( ctx )->deleted;
  *msg = (fd_snapmk_msg_deleted_t) {
    .slot      = inode->incr_slot!=ULONG_MAX ? inode->incr_slot : inode->full_slot,
    .base_slot = inode->incr_slot!=ULONG_MAX ? inode->full_slot : ULONG_MAX,
    .pool_idx  = snap_pool_idx
  };
  fd_cstr_ncpy( msg->name, inode->name, sizeof(msg->name) );
  snapmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_DELETED );

  /* do a blocking wait for the file to become free  */

  int snap_fd = FD_SNAP_FD( snap_pool_idx );
  struct flock lock = {
    .l_type   = F_WRLCK,
    .l_whence = SEEK_SET
  };
  if( FD_UNLIKELY( fcntl( snap_fd, F_SETLKW, &lock ) ) ) {
    FD_LOG_ERR(( "fcntl(F_SETLKW, %s) failed: %i-%s",
                 ctx->pool[ snap_pool_idx ].name, errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_INFO(( "evicting old snapshot file: %s", inode->name ));
  if( FD_UNLIKELY( ftruncate( snap_fd, 0L ) ) ) {
    FD_LOG_ERR(( "ftruncate(%s) failed: %s", inode->name, fd_io_strerror( errno ) ));
  }

  char partial_name[ sizeof(inode->name) ];
  fd_snap_pool_partial_name( partial_name, snap_pool_idx );
  if( FD_UNLIKELY( renameat( ctx->snap_dir_fd, inode->name, ctx->snap_dir_fd, partial_name ) ) ) {
    FD_LOG_ERR(( "renameat(%s, %s) failed: %s", inode->name, partial_name, fd_io_strerror( errno ) ));
  }
  fd_cstr_ncpy( inode->name, partial_name, sizeof(inode->name) );
  inode->full_slot = ULONG_MAX;
  inode->incr_slot = ULONG_MAX;
  return snap_pool_idx;
}

/* snap_start boots the snap production pipeline.
   Returns:
   - 1 if snapshot production was started
   - 0 if system is not ready yet, and start attempt should be retried
   - -1 if attempt was rejected */

static int
snap_start( fd_snapmk_t *                  ctx,
            fd_stem_context_t *            stem,
            fd_replay_snap_start_t const * msg ) {
  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
  case SNAPMK_STATE_SLEEP:
    break;
  case SNAPMK_STATE_STARTUP:
  case SNAPMK_STATE_STARTUP_BURST:
    return 0; /* not ready yet */
  default:
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  FD_TEST( bank );
  ctx->bank = bank;

  int incremental = msg->slot!=msg->base_slot;
  if( FD_UNLIKELY( incremental ) ) {
    FD_CHECK_CRIT( msg->base_slot!=ULONG_MAX, "incremental snapshot requested without a base full snapshot" );
    ctx->base_slot = msg->base_slot;
  } else {
    ctx->base_slot = ULONG_MAX;
  }
  ctx->incremental = incremental;

  /* wait for accdb root to match published root */
  fd_accdb_fork_id_t root_fork_id = bank->accdb_fork_id;
  FD_TEST( root_fork_id.val!=USHORT_MAX );
  if( FD_UNLIKELY( __atomic_load_n( &ctx->accdb_root_fork->val, __ATOMIC_ACQUIRE )!=root_fork_id.val ) ) {
    return 0; /* not ready */
  }
  ulong root_generation = __atomic_load_n( &ctx->accdb_shfork[ root_fork_id.val ].generation, __ATOMIC_ACQUIRE );

  /* wait for accdb to disable compaction */
  ulong sync_req = incremental ? FD_ACCDB_SNAPSHOT_SYNC_START_INCR
                               : FD_ACCDB_SNAPSHOT_SYNC_START_FULL;
  ulong sync_ack = snapshot_sync_request( ctx, FD_ACCDB_SNAPSHOT_SYNC_IDLE, sync_req );
  if( FD_UNLIKELY( sync_ack==FD_ACCDB_SNAPSHOT_SYNC_FAIL ) ) {
    FD_LOG_WARNING(( "cannot create incremental snapshot, too many accounts changed (increase [snapshots.max_incremental_snapshot_accounts])" ));
    snapshot_sync_transition( ctx, FD_ACCDB_SNAPSHOT_SYNC_FAIL, FD_ACCDB_SNAPSHOT_SYNC_DONE, FD_ACCDB_SNAPSHOT_SYNC_IDLE );
    ctx->state = SNAPMK_STATE_FAIL;
    return -1;
  }
  if( FD_UNLIKELY( sync_ack!=FD_ACCDB_SNAPSHOT_SYNC_RUNNING ) ) {
    FD_LOG_CRIT(( "unexpected accdb snapshot sync state %lu", sync_ack ));
  }

  /* user might have changed available snapshots */
  fd_snap_pool_recover( ctx->snap_dir_fd, ctx->snap_dir, ctx->pool, ctx->snap_max );

  /* final name of snap (during compression has a "partial" name) */
  uchar snap_hash[ 32 ];
  fd_blake3_hash( ctx->bank->f.lthash.bytes, FD_LTHASH_LEN_BYTES, snap_hash );
  char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( snap_hash, NULL, encoded_hash );
  if( FD_UNLIKELY( incremental ) ) {
    FD_TEST( fd_cstr_printf_check( ctx->final_name, FD_SNAP_NAME_MAX, NULL,
             "incremental-snapshot-%lu-%lu-%s.tar.zst", ctx->base_slot, ctx->bank->f.slot, encoded_hash ) );
  } else {
    FD_TEST( fd_cstr_printf_check( ctx->final_name, FD_SNAP_NAME_MAX, NULL,
             "snapshot-%lu-%s.tar.zst", ctx->bank->f.slot, encoded_hash ) );
  }

  uint snap_idx = snap_pool_acquire( ctx, stem );
  if( FD_UNLIKELY( snap_idx==UINT_MAX ) ) {
    snapshot_sync_transition( ctx, FD_ACCDB_SNAPSHOT_SYNC_RUNNING, FD_ACCDB_SNAPSHOT_SYNC_DONE, FD_ACCDB_SNAPSHOT_SYNC_IDLE );
    return 0; /* not ready */
  }
  ctx->snap_idx = snap_idx;
  ctx->snap_fd  = FD_SNAP_FD( ctx->snap_idx );

  snapmk_msg_alloc( ctx )->started = (fd_snapmk_msg_started_t) {
    .slot      = ctx->bank->f.slot,
    .base_slot = ctx->base_slot,
    .pool_idx  = ctx->snap_idx
  };
  snapmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_STARTED );

  if( FD_UNLIKELY( ftruncate( ctx->snap_fd, 0L ) ) ) {
    FD_LOG_ERR(( "ftruncate(%s) failed: %i-%s", ctx->pool[ ctx->snap_idx ].name, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( lseek( ctx->snap_fd, 0L, SEEK_SET )<0L ) ) {
    FD_LOG_ERR(( "lseek(%s) failed: %i-%s", ctx->pool[ ctx->snap_idx ].name, errno, fd_io_strerror( errno ) ));
  }

  atomic_store_explicit( ctx->file_off_p, 0UL, memory_order_relaxed );

  /* compression buffers */

  ctx->raw_buf.size  = 0UL;
  ctx->raw_buf.pos   = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;
  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  /* misc */

  fd_ssmanifest_writer_init( ctx->manifest_writer, bank );

  /* accdb cache/disk parsers */

  fd_backup_cache_reset( ctx->acc_cache, root_generation );
  *ctx->accparse = (fd_snapmk_accparse_t) {
    .acc_keep           = 1U,
    .acc_map            = ctx->acc_cache->acc_map,
    .acc_pool           = ctx->acc_cache->acc_pool,
    .visited_set        = ctx->visited_set,
    .max_accounts       = ctx->acc_cache->max_accounts,
    .acc_map_seed       = ctx->acc_cache->acc_map_seed,
    .chain_mask         = ctx->acc_cache->chain_mask,
    .epoch_slot         = ctx->acc_cache->epoch_slot,
    .epoch              = ctx->acc_cache->epoch,
    .root_generation    = (uint)root_generation
  };

  ctx->delta.chain_idx = 0UL;
  ctx->delta.ele_idx   = UINT_MAX;

  visited_set_null( ctx->visited_set );

  ctx->state              = SNAPMK_STATE_START;
  ctx->zp_ready           = 0UL;
  ctx->disk_out_idx       = -1;
  ctx->disk_batch_pending = 0;
  ctx->start_time         = fd_log_wallclock();
  if( FD_UNLIKELY( incremental ) ) {
    ctx->metrics.snapshots_created_incremental++;
    ctx->metrics.last_snapshot_slot_started_incremental = ctx->bank->f.slot;
  } else {
    ctx->metrics.snapshots_created_full++;
    ctx->metrics.last_snapshot_slot_started_full = ctx->bank->f.slot;
  }
  broadcast_prepare( ctx );

  if( FD_UNLIKELY( incremental ) ) {
    FD_LOG_INFO(( "incremental snapshot creation started (slot %lu, base slot %lu)",
                  ctx->bank->f.slot, ctx->base_slot ));
  } else {
    FD_LOG_INFO(( "snapshot creation started (slot %lu)", ctx->bank->f.slot ));
  }
  return 1;
}

/* fd_snapmk_accparse_publish produces an account-aligned frag from
   accumulated source data.  Should be called after each accparse_insert
   calls.  Returns meta if a frag was produced, NULL otherwise.
   meta->sig set to the wksp-relative pos.  meta->tspub is the account
   data byte count for this frag.  meta->ctl.som=1 set if this is the
   first frag of an account, meta->ctl.eom=1 set if it's the last (both
   if the frag fully contains the account).

   FIXME this is ridiculously long */

static inline fd_frag_meta_t *
fd_snapmk_accparse_publish( fd_snapmk_accparse_t * parse,
                            fd_frag_meta_t *       meta ) {
  for(;;) {
    if( FD_UNLIKELY( parse->pub_pending ) ) {
      meta->sig    = parse->pub_gaddr;
      meta->chunk  = parse->pub_acc_idx;
      meta->sz     = 0;
      meta->ctl    = (ushort)fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK, parse->pub_som, parse->pub_eom, 0 );
      meta->tsorig = 0U;
      meta->tspub  = (uint)parse->pub_sz;
      parse->pub_pending = 0;
      return meta;
    }

    if( FD_UNLIKELY( !parse->data_sz ) ) return NULL;

    if( FD_UNLIKELY( !parse->acc_active ) ) {
      if( FD_UNLIKELY( !parse->meta_sz ) ) {
        parse->acc_file_off = parse->src_off;
        parse->acc_snap_sz  = 0U;
        parse->acc_idx      = UINT_MAX;
        parse->acc_keep     = 1U;
      }

      ulong meta_rem = sizeof(fd_accdb_disk_meta_t) - (ulong)parse->meta_sz;
      ulong take     = fd_ulong_min( meta_rem, parse->data_sz );
      fd_memcpy( parse->buf + parse->meta_sz, parse->data, take );
      parse->meta_sz   += (uint)take;
      parse->data      += take;
      parse->data_sz   -= take;
      parse->src_gaddr += take;
      parse->src_off   += take;

      if( FD_UNLIKELY( parse->meta_sz < sizeof(fd_accdb_disk_meta_t) ) ) continue;

      ulong data_sz = (ulong)FD_ACCDB_SIZE_DATA( parse->meta.size );
      ulong snap_sz = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_sz, 8UL );
      if( FD_UNLIKELY( data_sz>UINT_MAX ) ) {
        FD_LOG_CRIT(( "accdb disk account data too large (%lu bytes)", data_sz ));
      }
      if( FD_UNLIKELY( snap_sz>UINT_MAX ) ) {
        FD_LOG_CRIT(( "snapshot account record too large (%lu bytes)", snap_sz ));
      }

      parse->accounts_seen++;
      parse->acc_active  = 1;
      parse->acc_off     = 0U;
      parse->acc_sz      = (uint)data_sz;
      parse->acc_snap_sz = (uint)snap_sz;
      parse->meta_sz     = 0U;
      parse->acc_keep    = (uint)fd_snapmk_accparse_keep( parse );

      if( FD_UNLIKELY( !parse->acc_sz ) ) {
        if( FD_LIKELY( parse->acc_keep ) ) {
          parse->pub_gaddr   = 0UL;
          parse->pub_off     = parse->src_off;
          parse->pub_sz      = 0U;
          parse->pub_acc_idx = parse->acc_idx;
          parse->pub_snap_sz = parse->acc_snap_sz;
          parse->pub_size    = parse->meta.size;
          memcpy( &parse->pub_pubkey, parse->meta.pubkey, sizeof(fd_pubkey_t) );
          memcpy( &parse->pub_owner,  parse->meta.owner,  sizeof(fd_pubkey_t) );
          parse->pub_som     = 1;
          parse->pub_eom     = 1;
          parse->pub_pending = 1;
        }
        parse->acc_active = 0;
        parse->acc_off    = 0U;
        parse->acc_sz     = 0U;
        continue;
      }

      continue;
    }

    ulong acc_rem = (ulong)parse->acc_sz - (ulong)parse->acc_off;
    ulong take    = fd_ulong_min( acc_rem, parse->data_sz );
    if( FD_UNLIKELY( !take ) ) return NULL;

    if( FD_UNLIKELY( !parse->acc_keep ) ) {
      parse->acc_off   += (uint)take;
      parse->data      += take;
      parse->data_sz   -= take;
      parse->src_gaddr += take;
      parse->src_off   += take;
      if( FD_UNLIKELY( parse->acc_off==parse->acc_sz ) ) {
        parse->acc_active = 0;
        parse->acc_off    = 0U;
        parse->acc_sz     = 0U;
        parse->acc_keep   = 1U;
      }
      continue;
    }

    uint old_acc_off = parse->acc_off;
    parse->pub_gaddr   = parse->src_gaddr;
    parse->pub_off     = parse->src_off;
    parse->pub_sz      = (uint)take;
    parse->pub_acc_idx = parse->acc_idx;
    parse->pub_snap_sz = parse->acc_snap_sz;
    parse->pub_size    = parse->meta.size;
    memcpy( &parse->pub_pubkey, parse->meta.pubkey, sizeof(fd_pubkey_t) );
    memcpy( &parse->pub_owner,  parse->meta.owner,  sizeof(fd_pubkey_t) );
    parse->pub_som     = !old_acc_off;
    parse->pub_eom     = ( old_acc_off + take )==parse->acc_sz;
    parse->pub_pending = 1;

    parse->acc_off   += (uint)take;
    parse->data      += take;
    parse->data_sz   -= take;
    parse->src_gaddr += take;
    parse->src_off   += take;

    if( FD_UNLIKELY( parse->pub_eom ) ) {
      parse->acc_active = 0;
      parse->acc_sz     = 0U;
      parse->acc_off    = 0U;
    }
  }

}

/* snapzp_stamp_shadow tracks the snaprd frag seq corresponding to an
   upcoming snapmk_zp publish. */

static inline void
snapzp_stamp_shadow( fd_snapmk_t * ctx,
                     ulong         out_idx,
                     ulong         pub_seq ) {
  ctx->rd_shadow[ out_idx ][ pub_seq & (FD_SNAPMK_ZP_DEPTH-1UL) ] = ctx->rd_seq;
}

/* snaprd_frag ingests a new accdb disk data frag from snaprd. */

static int
snaprd_frag( fd_snapmk_t *       ctx,
             fd_stem_context_t * stem,
             ulong               seq,
             ulong               sig,
             ulong               chunk,
             ulong               ctl,
             ulong               tspub ) {
  ulong frag_sz = tspub;
  FD_CHECK_CRIT( ctx->state==SNAPMK_STATE_ACCDB_DISK, "lifecycle bug" );
  FD_CHECK_CRIT( fd_frag_meta_ctl_orig( ctl )==FD_BACKUP_ORIG_DISK_FRAG, "unexpected snaprd frag orig" );
  FD_CHECK_CRIT( frag_sz<=FD_BACKUP_RD_MTU && frag_sz<UINT_MAX, "invalid snaprd frag data size" );
  FD_CHECK_CRIT( frag_sz || fd_frag_meta_ctl_eom( ctl ), "empty snaprd frag" );

  fd_snapmk_accparse_t * parse = ctx->accparse;
  ctx->rd_seq = seq;
  if( FD_LIKELY( !parse->input_active ) ) {
    uchar const * data = fd_chunk_to_laddr_const( ctx->rd_in_mem, chunk );
    parse->data            = data;
    parse->data_sz         = frag_sz;
    parse->src_gaddr       = fd_wksp_gaddr_fast( ctx->rd_in_mem, data );
    parse->src_off         = sig;
    parse->frag_base_gaddr = fd_wksp_gaddr_fast( ctx->rd_in_mem, data );
    parse->pf_cursor       = data; /* WTF is pf_cursor */
    parse->input_active    = 1;
  }

  for(;;) {
    /* (A) Flush a previously-staged batch once an output link frees up.
       A batch is self-contained within one snaprd frag, so it may be
       routed to any ready zp tile (no disk_out_idx pinning). */
    if( FD_UNLIKELY( ctx->disk_batch_pending ) ) {
      if( FD_UNLIKELY( !ctx->zp_ready ) ) return 1;
      ulong out_idx = zp_rr_next( ctx );
      ulong out_chunk;
      void * payload = zp_alloc( ctx, out_idx, sizeof(fd_backup_disk_batch_msg_t), &out_chunk );
      fd_memcpy( payload, ctx->disk_batch, sizeof(fd_backup_disk_batch_msg_t) );
      ulong ctl_batch = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK_BATCH, 1, 1, 0 );
      snapzp_stamp_shadow( ctx, out_idx, stem->seqs[ out_idx ] );
      zp_publish( ctx, stem, out_idx, ctx->disk_batch_base_gaddr, out_chunk,
                  sizeof(fd_backup_disk_batch_msg_t), ctl_batch, 0UL, 0UL );
      ctx->disk_batch_pending = 0;
      return 1;
    }


    /* (B) Stage a batch of wholly-contained accounts (no straddle).
       Staging consumes the accounts into ctx->disk_batch; (A) flushes
       it on the next iteration once credit is available. */
    if( FD_LIKELY( ctx->disk_out_idx < 0 ) ) {
      ulong base_gaddr;
      ulong n = fd_snapmk_accparse_publish_batch( parse, ctx->disk_batch, &base_gaddr );
      if( n ) {
        ctx->disk_batch_pending    = 1;
        ctx->disk_batch_base_gaddr = base_gaddr;
        continue;
      }
    }

    /* (C) Single-account fallback for straddling / mid-record accounts. */
    ulong out_idx = (ulong)ctx->disk_out_idx;
    if( FD_LIKELY( out_idx<ctx->zp_cnt ) ) {
      if( FD_UNLIKELY( !stem->cr_avail[ out_idx ] ) ) return 1;
    } else {
      if( FD_UNLIKELY( !ctx->zp_ready ) ) return 1;
      out_idx = zp_rr_next( ctx );
    }

    fd_frag_meta_t meta[1];
    if( FD_UNLIKELY( !fd_snapmk_accparse_publish( parse, meta ) ) ) {
      parse->input_active = 0;
      /* A prestaged batch references the current frag's bytes and must
          be drained before this frag is released (publish_batch above
          returns 0 only once the prestage is empty). */
      FD_CHECK_ERR( !parse->ps_cnt, "prestaged batch outlived its frag" );
      if( FD_UNLIKELY( fd_frag_meta_ctl_eom( ctl ) ) ) {
        if( FD_UNLIKELY( parse->meta_sz || parse->acc_active || parse->pub_pending ) ) {
          FD_LOG_CRIT(( "snaprd stream ended mid-account record" ));
        }
        ctx->disk_out_idx = -1;
        barrier_install( ctx, stem );
        broadcast_prepare( ctx );
        ctx->state = SNAPMK_STATE_ACCDB_DISK_FLUSH;
      }
      return 0;
    }

    /* An account may straddle multiple snaprd frags.  The first frag of
       an account (som) carries the fd_backup_disk_msg_t header and pins
       the account to out_idx; continuation frags carry data only and
       must go to the same zp tile, until eom unpins it. */
    int   som       = fd_frag_meta_ctl_som( meta->ctl );
    int   eom       = fd_frag_meta_ctl_eom( meta->ctl );
    ulong out_chunk = 0UL;
    ulong out_sz    = 0UL;
    if( FD_UNLIKELY( som ) ) {
      ctx->disk_out_idx = (int)out_idx;
      fd_backup_disk_msg_t * frag = zp_alloc( ctx, out_idx, sizeof(fd_backup_disk_msg_t), &out_chunk );
      frag->pubkey  = parse->pub_pubkey;
      frag->owner   = parse->pub_owner;
      frag->size    = parse->pub_size;
      frag->acc_idx = parse->pub_acc_idx;
      frag->snap_sz = parse->pub_snap_sz;
      frag->data_sz = (uint)meta->tspub;
      out_sz = sizeof(fd_backup_disk_msg_t);
    }

    snapzp_stamp_shadow( ctx, out_idx, stem->seqs[ out_idx ] );
    zp_publish( ctx, stem, out_idx, meta->sig, out_chunk, out_sz, meta->ctl, meta->tsorig, meta->tspub );
    if( FD_UNLIKELY( eom ) ) ctx->disk_out_idx = -1;
    return 1;
  }
}

/* returnable_frag is called for every input frag. */

static int
returnable_frag( fd_snapmk_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)sz; (void)tsorig;
  fd_startup_gate_busy( ctx->startup_gate );
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    switch( sig ) {
    case REPLAY_SIG_SNAP_START: {
      fd_replay_snap_start_t const * msg = fd_chunk_to_laddr_const( ctx->replay_in_mem, chunk );
      int res = snap_start( ctx, stem, msg );
      if( res==0 ) return 1; /* not ready yet */
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected replay_snapmk message (sig=%lu)", sig ));
    }
    ctx->replay_in_seq_cons = fd_seq_inc( seq, 1UL );
    return 0;
  case IN_KIND_SNAPRD:
    return snaprd_frag( ctx, stem, seq, sig, chunk, ctl, tspub );
  default:
    FD_LOG_CRIT(( "unexpected msg from link %lu with sig %lu", in_idx, sig ));
  }
}

static void
metrics_write( fd_snapmk_t * ctx ) {
  FD_MCNT_SET  ( SNAPMK, SNAPSHOTS_CREATED_FULL,                  ctx->metrics.snapshots_created_full                  );
  FD_MCNT_SET  ( SNAPMK, SNAPSHOTS_CREATED_INCREMENTAL,           ctx->metrics.snapshots_created_incremental           );
  FD_MGAUGE_SET( SNAPMK, LAST_SNAPSHOT_SLOT_STARTED_FULL,         ctx->metrics.last_snapshot_slot_started_full         );
  FD_MGAUGE_SET( SNAPMK, LAST_SNAPSHOT_SLOT_STARTED_INCREMENTAL,  ctx->metrics.last_snapshot_slot_started_incremental  );
  FD_MGAUGE_SET( SNAPMK, LAST_SNAPSHOT_SLOT_FINISHED_FULL,        ctx->metrics.last_snapshot_slot_finished_full        );
  FD_MGAUGE_SET( SNAPMK, LAST_SNAPSHOT_SLOT_FINISHED_INCREMENTAL, ctx->metrics.last_snapshot_slot_finished_incremental );

  FD_MCNT_SET  ( SNAPMK, BYTES_COMPRESSED,            ctx->metrics.bytes_compressed );
  FD_MCNT_SET  ( SNAPMK, BYTES_WRITTEN,               ctx->metrics.bytes_written    );
  FD_MCNT_SET  ( SNAPMK, IO_BLOCKED_DURATION_SECONDS, ctx->metrics.io_blocked_ticks );
  FD_MCNT_SET  ( SNAPMK, COMPRESS_DURATION_SECONDS,   ctx->metrics.compress_ticks   );
}

#define STEM_BURST SNAPMK_STEM_BURST
#define STEM_LAZY  SNAPMK_STEM_LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapmk_t)
#define STEM_CALLBACK_RECV_CREDIT     recv_credit
#define STEM_CALLBACK_CHECK_CREDIT    check_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

/* snapmk_run contains a bunch of boilerplate to hijack flow control
   away from stem. */

static void
snapmk_run( fd_topo_t *      topo,
            fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = (fd_snapmk_t *)fd_ulong_align_up( (ulong)fd_topo_obj_laddr( topo, tile->tile_obj_id ), alignof(fd_snapmk_t) );

  fd_frag_meta_t const * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong *                in_fseq  [ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    in_mcache[ polled_in_cnt ] = link->mcache;
    FD_TEST( in_mcache[ polled_in_cnt ] );
    /* Redirect links with custom flow control to local shadows. */
    if( 0==strcmp( link->name, "snaprd_out" ) ) {
      /* snaprd_out fseq set using custom logic, disable stem fseq updates */
      in_fseq[ polled_in_cnt ] = &ctx->rd_fseq_dummy;
    } else {
      in_fseq[ polled_in_cnt ] = tile->in_link_fseq[ i ];
    }
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1UL;
  }

  fd_frag_meta_t * out_mcache[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    FD_TEST( out_mcache[ i ] );
  }

  ulong            reliable_cons_cnt = 0UL;
  ulong            cons_out [ FD_TOPO_MAX_LINKS ];
  ulong *          cons_fseq[ FD_TOPO_MAX_LINKS ];
  volatile ulong * cons_slow[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    ulong polled_in_idx = 0UL;
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      int is_polled = consumer_tile->in_link_poll[ j ];
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out [ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          cons_slow[ reliable_cons_cnt ] = fd_metrics_link_in( consumer_tile->metrics, polled_in_idx ) + FD_METRICS_COUNTER_LINK_SLOW_OFF;
          reliable_cons_cnt++;
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
      if( FD_LIKELY( is_polled ) ) polled_in_idx++;
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)fd_ulong_hash( (ulong)fd_tickcount() + tile->id ), 0UL ) ) );

  uchar __attribute__((aligned(FD_STEM_SCRATCH_ALIGN))) stem_scratch[ stem_scratch_footprint( polled_in_cnt, tile->out_cnt, reliable_cons_cnt ) ];

  stem_run1( polled_in_cnt, in_mcache, in_fseq,
             tile->out_cnt, out_mcache,
             reliable_cons_cnt, cons_out, cons_fseq, cons_slow,
             SNAPMK_STEM_BURST, SNAPMK_STEM_LAZY,
             rng, stem_scratch, ctx );
}

fd_topo_run_tile_t fd_tile_snapmk = {
  .name                     = "snapmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = snapmk_run,
  .allow_renameat           = 1
};
