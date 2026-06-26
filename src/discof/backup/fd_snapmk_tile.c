#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fd_backup.h"
#include "fd_backup_cache.h"
#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../tango/fseq/fd_fseq.h"

#define SET_NAME visited_set
#include "../../util/tmpl/fd_set_dynamic.c"

#define FD_ZSTD_LEVEL 1
#define RAW_BUF_SZ    (32UL<<20)
#define COMP_BUF_SZ   ZSTD_COMPRESSBOUND( RAW_BUF_SZ )

struct fd_snapmk {
  uint state;

  fd_backup_cache_t acc_cache[1];
  visited_set_t *   visited_set;

  int  out_fd;
  int  snap_dir_fd;
  char out_path  [ PATH_MAX ];
  char snap_dir  [ PATH_MAX ];
  char final_name[ FD_BACKUP_NAME_MAX ];
  char wip_name  [ FD_BACKUP_NAME_MAX ];

  ulong            zp_cnt; /* [0,zp_cnt] out links are to zp */
  ulong volatile * zp_file_off;
  ulong *          accdb_epoch_idx;

  ulong in_idle_cnt;

  ulong out_meta_idx;
  ulong out_ready;         /* bit set */
  ulong out_flush_pending; /* bit set */

  fd_banks_t *    banks;
  fd_bank_t *     bank;
  fd_txncache_t * txncache;
  fd_wksp_t *     replay_in_mem;
  fd_ssmanifest_writer_t manifest_writer[1];
  fd_txncache_writer_t   txncache_writer[1];
  fd_accdb_shmem_t * accdb_shmem;

  ulong manifest_pad;
  ulong status_cache_pad;
  long  start_time;

  /* IPC */
  fd_backup_frag_t * scan_batch[ FD_TOPO_MAX_TILE_OUT_LINKS ];
  ushort             in_kind   [ FD_TOPO_MAX_TILE_IN_LINKS  ];

  /* account index */
  ulong                acc_seed;
  ulong                acc_chain_mask;
  uint *               acc_map;
  fd_accdb_accmeta_t * acc_pool;

  /* account data cache */
  uchar * cache    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong   cache_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* accdb root fork */
  fd_accdb_fork_shmem_t const * accdb_shfork;
  fd_accdb_fork_id_t const *    accdb_root_fork;

  /* output buffer */
  ZSTD_CCtx *    zst;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;
  uchar raw [ RAW_BUF_SZ  ];
  uchar comp[ COMP_BUF_SZ ];

  struct {
    ulong compress_ticks;
    ulong io_ticks;
    ulong bytes_compressed;
    ulong bytes_written;
  } metrics;
};

typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1

/* snapmk state machine */

#define SNAPMK_STATE_IDLE            0 /* clean, waiting for job */
#define SNAPMK_STATE_START           1
#define SNAPMK_STATE_TAR_HEADERS     2
#define SNAPMK_STATE_MANIFEST        3 /* writing manifest */
#define SNAPMK_STATE_ACCOUNTS_CACHE  4 /* writing cached accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH1 5 /* writing cached accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH2 6 /* done writing accounts, flush pipeline */
#define SNAPMK_STATE_ACCOUNTS_DRAIN  7 /* wait for flush to complete */
#define SNAPMK_STATE_STATUS_CACHE    8 /* writing status cache */
#define SNAPMK_STATE_EOF_MARKER      9 /* writing tar EOF marker */
#define SNAPMK_STATE_DONE           10 /* done, notify replay tile */
#define SNAPMK_STATE_FAIL           11 /* error state, doing cleanup */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_snapmk_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong max_live_slots = tile->snapmk.max_live_slots;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t)                       );
  l = FD_LAYOUT_APPEND( l, visited_set_align(), visited_set_footprint( tile->snapmk.max_accounts ) );
  l = FD_LAYOUT_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots )   );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  fd_cstr_ncpy( ctx->snap_dir, tile->snapmk.out_path, PATH_MAX );
  char * last_slash = strrchr( ctx->snap_dir, '/' );
  if( FD_LIKELY( last_slash ) ) *last_slash = '\0';

  int dir_fd = open( ctx->snap_dir, O_RDONLY|O_DIRECTORY );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", ctx->snap_dir, fd_io_strerror( errno ) ));
  }
  ctx->snap_dir_fd = dir_fd;
  ctx->out_fd      = -1;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->snap_dir_fd;
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO; /* accounts db readonly fd */
  return out_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong max_live_slots = tile->snapmk.max_live_slots;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapmk_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  void *        _visited = FD_SCRATCH_ALLOC_APPEND( l, visited_set_align(), visited_set_footprint( tile->snapmk.max_accounts ) );
  void *        _zstd    = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  void *        _txnc_lj = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots ) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( end==(ulong)scratch + scratch_footprint( tile ) );

  ctx->state = SNAPMK_STATE_IDLE;
  ctx->visited_set = visited_set_join( visited_set_new( _visited, tile->snapmk.max_accounts ) );
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
  ctx->zp_file_off = fd_fseq_app_laddr( zp_fseq );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapmk.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  ctx->accdb_shmem = accdb_shmem_ro;
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.accdb_epoch_fseq_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb_epoch_idx = epoch_fseq;
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = ULONG_MAX;
  fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro );
  {
    FD_SCRATCH_ALLOC_INIT( l, accdb_shmem_ro );
    FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN, sizeof(fd_accdb_shmem_t) );
    ctx->accdb_shfork = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t) );
  }
  ctx->accdb_root_fork = &accdb_shmem_ro->root_fork_id;

  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "replay_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
      fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->replay_in_mem = link_wksp->wksp;
    } else {
      FD_LOG_ERR(( "Unexpected input link \"%s\"", link->name ));
    }
  }

  FD_TEST( tile->out_cnt >= 2 );
  FD_TEST( tile->out_cnt <= SNAPZP_TILE_MAX );
  ctx->zp_cnt = tile->out_cnt - 1UL;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0!=strcmp( link->name, "snapmk_zp" ) ) {
      FD_LOG_ERR(( "Unexpected output link \"%s\"", link->name ));
    }
    FD_TEST( link->mcache );
    ctx->scan_batch[ i ] = link->dcache;
  }
  ctx->out_meta_idx = tile->out_cnt - 1UL;
  if( 0!=strcmp( topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name, "snapmk_replay" ) ) {
    FD_LOG_ERR(( "Unexpected output link \"%s\"", topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name ));
  }

  ctx->zst = ZSTD_initStaticCStream( _zstd, ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_TEST( ctx->zst );
  ulong zst_err;
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_ZSTD_LEVEL );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->raw_buf  = (ZSTD_inBuffer ){ .src = ctx->raw,  .size = 0UL         };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = ctx->comp, .size = COMP_BUF_SZ };
}

static void
update_flow_control( fd_snapmk_t *             ctx,
                     fd_stem_context_t const * stem ) {
  ulong out_ready = 0UL;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    out_ready |= fd_ulong_if( !!stem->cr_avail[ i ], 1UL<<i, 0UL );
  }
  ctx->out_ready = out_ready;
}

static int
all_out_links_caught_up( fd_snapmk_t *             ctx,
                         fd_stem_context_t const * stem ) {
  _Bool caught_up = 1;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    if( stem->cr_avail[ i ] < stem->depths[ i ] ) caught_up = 0;
  }
  return caught_up;
}

static int
accdb_compaction_paused( fd_snapmk_t * ctx,
                         ulong         snapshot_epoch ) {
  fd_accdb_shmem_t const * accdb = ctx->accdb_shmem;
  fd_accdb_partition_t const * partition_pool =
      (fd_accdb_partition_t const *)( (uchar const *)accdb + accdb->partition_pool_off );

  ulong partition_max = FD_VOLATILE_CONST( accdb->partition_max );
  for( ulong partition_idx=0UL; partition_idx<partition_max; partition_idx++ ) {
    fd_accdb_partition_t const * partition = partition_pool_ele_const( partition_pool, partition_idx );

    if( FD_UNLIKELY( FD_VOLATILE_CONST( partition->compacting_now ) ) ) return 0;
    if( FD_UNLIKELY( FD_VOLATILE_CONST( partition->queued ) &&
                     FD_VOLATILE_CONST( partition->compaction_ready_epoch )<snapshot_epoch ) ) return 0;
  }

  return 1;
}

static void
pause_accdb_compaction( fd_snapmk_t * ctx ) {
  ulong snapshot_epoch = FD_VOLATILE_CONST( ctx->accdb_shmem->epoch );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = snapshot_epoch;
  FD_HW_MFENCE();

  while( FD_UNLIKELY( !accdb_compaction_paused( ctx, snapshot_epoch ) ) ) FD_YIELD();
}

static void
resume_accdb_compaction( fd_snapmk_t * ctx ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = ULONG_MAX;
  FD_COMPILER_MFENCE();
}

/* check_credit is called every run loop iteration */

static void
check_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               charge_busy,
              int *               is_backpressured ) {
  (void)stem; (void)is_backpressured;
  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    if( ctx->in_idle_cnt++ > 128 ) fd_log_sleep( (long)1e6 );
    *charge_busy = 0;
    *is_backpressured = 0;
    break;
  case SNAPMK_STATE_START:
  case SNAPMK_STATE_ACCOUNTS_CACHE:
    *is_backpressured = 0;
    if( FD_UNLIKELY( !ctx->out_ready ) ) {
      update_flow_control( ctx, stem );
      if( FD_UNLIKELY( !ctx->out_ready ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH1:
  case SNAPMK_STATE_ACCOUNTS_FLUSH2:
  case SNAPMK_STATE_ACCOUNTS_DRAIN:
    /* Block until all zp tiles are caught up */
    if( !all_out_links_caught_up( ctx, stem ) ) {
      *is_backpressured = 1;
      return;
    }
    *is_backpressured = 0;
    break;
  }
}

static void
flush_buffer( fd_snapmk_t *     ctx,
              ZSTD_EndDirective directive ) {

  /* Compress chunk */
  long t0 = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, directive );
  ctx->metrics.bytes_compressed += ctx->raw_buf.pos;
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2 failed: %s", ZSTD_getErrorName( ret ) ));
  }

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
  long t1 = fd_tickcount();
  ctx->metrics.compress_ticks += (ulong)( t1 - t0 );

  /* Write compressed bytes to file */
  ulong comp_wr_;
  ulong comp_sz = ctx->comp_buf.pos;
  int wr_err = fd_io_write(
      ctx->out_fd,
      ctx->comp,
      comp_sz, comp_sz,
      &comp_wr_ );
  if( FD_UNLIKELY( wr_err ) ) {
    FD_LOG_ERR(( "fd_io_write failed: %s", fd_io_strerror( wr_err ) ));
  }
  if( FD_UNLIKELY( comp_wr_ != comp_sz ) ) {
    FD_LOG_ERR(( "fd_io_write did not write full buffer (expected %lu bytes, wrote %lu bytes)", comp_sz, comp_wr_ ));
  }
  long t2 = fd_tickcount();
  ctx->metrics.bytes_written += comp_sz;
  ctx->metrics.io_ticks += (ulong)( t2 - t1 );
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;
}

static void
align_stream( fd_snapmk_t * ctx ) {
  long off = lseek( ctx->out_fd, 0L, SEEK_CUR );
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
    uchar frame_hdr[ 8 ];
    FD_STORE( uint, frame_hdr,   ZSTD_MAGIC_SKIPPABLE_START );
    FD_STORE( uint, frame_hdr+4, (uint)( pad_sz-8 ) );
    ulong wr_sz_;
    int err = fd_io_write( ctx->out_fd, frame_hdr, 8UL, 8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
    static uchar const zero[ 4096UL ] = {0};
    err = fd_io_write( ctx->out_fd, zero, pad_sz-8UL, pad_sz-8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
  }
  __atomic_store_n( ctx->zp_file_off, aoff, __ATOMIC_RELEASE );
}

/* after_credit is called if we can publish at least one frag */

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;

  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    break;
  case SNAPMK_STATE_START: {
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong seq = stem->seqs[ i ];
      fd_backup_frag_t * frag = ctx->scan_batch[ i ] + (seq & (stem->depths[ i ]-1));
      memset( frag, 0, sizeof(fd_backup_frag_t) );
      ulong name_len = strlen( ctx->wip_name );
      FD_TEST( name_len < FD_BACKUP_NAME_MAX );
      frag->start.name_len = (ushort)name_len;
      fd_memcpy( frag->start.name, ctx->wip_name, name_len+1UL );
      ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_START, 0, 0, 0 );
      fd_stem_publish( stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      ctx->out_ready         &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
    }
    if( !ctx->out_flush_pending ) {
      ctx->state = SNAPMK_STATE_TAR_HEADERS;
    }
    break;
  }
  case SNAPMK_STATE_TAR_HEADERS: {
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

    flush_buffer( ctx, ZSTD_e_end );
    ctx->state = SNAPMK_STATE_MANIFEST;
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_MANIFEST: {
    if( FD_UNLIKELY( ctx->raw_buf.size + FD_SSMANIFEST_BUF_MIN > RAW_BUF_SZ ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      *charge_busy = 1;
      return;
    }
    ulong buf_rem = RAW_BUF_SZ - ctx->raw_buf.size;
    ulong chunk_sz = fd_snap_manifest_serialize(
        ctx->manifest_writer,
        (uchar *)ctx->raw_buf.src + ctx->raw_buf.size,
        buf_rem );
    ctx->raw_buf.size += chunk_sz;
    if( FD_UNLIKELY( !chunk_sz ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      if( ctx->manifest_pad ) {
        fd_memset( ctx->raw, 0, ctx->manifest_pad );
        ctx->raw_buf.size = ctx->manifest_pad;
      }
      flush_buffer( ctx, ZSTD_e_end );
      ctx->state = SNAPMK_STATE_ACCOUNTS_CACHE;
      align_stream( ctx );
      *charge_busy = 1;
      return;
    }
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_CACHE: {
    int out_idx = fd_ulong_find_lsb( ctx->out_ready );
    ulong seq = stem->seqs[ out_idx ];
    fd_backup_frag_t * frag = ctx->scan_batch[ out_idx ] + (seq & (stem->depths[ out_idx ]-1));
    frag = fd_backup_cache_scan( ctx->acc_cache, frag );
    if( FD_UNLIKELY( !frag ) ) {
      ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH1;
      ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
      break;
    }

    /* remove duplicates
       first pass (fast), ILP-friendly/vectorizable check */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = frag->acc_cache.acc_idx[ i ];
      if( acc_idx==UINT_MAX ) continue;
      if( FD_UNLIKELY( visited_set_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
        frag->acc_cache.acc_idx[ i ] = UINT_MAX;
      }
    }
    /* second pass: intra-batch conflict detect */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = frag->acc_cache.acc_idx[ i ];
      if( acc_idx==UINT_MAX ) continue;
      if( FD_UNLIKELY( visited_set_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
        frag->acc_cache.acc_idx[ i ] = UINT_MAX;
        memset( frag->acc_cache.pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
        continue;
      }
      visited_set_insert( ctx->visited_set, (ulong)acc_idx );
    }

    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_CACHE, 0, 0, 0 );
    fd_stem_publish( stem, (ulong)out_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    _Bool blocked = !stem->cr_avail[ out_idx ];
    ctx->out_ready &= blocked ? ~fd_ulong_mask_bit( out_idx ) : ULONG_MAX;
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_FLUSH1:
  case SNAPMK_STATE_ACCOUNTS_FLUSH2: {
    /* Broadcast FLUSH packets */
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_FLUSH, 0, 0, 0 );
      fd_stem_publish( stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
    }
    if( !ctx->out_flush_pending ) {
      ctx->state = SNAPMK_STATE_ACCOUNTS_DRAIN;
    }
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_DRAIN: {
    if( FD_UNLIKELY( lseek( ctx->out_fd, 0L, SEEK_END )<0L ) ) {
      FD_LOG_ERR(( "lseek failed: %i-%s", errno, fd_io_strerror( errno ) ));
    }

    fd_txncache_writer_init( ctx->txncache_writer, ctx->txncache, ctx->bank->f.slot );
    ulong sc_sz = fd_txncache_writer_serialized_sz( ctx->txncache, ctx->bank->f.slot );

    ctx->raw_buf.pos = ctx->raw_buf.size = 0UL;
    fd_tar_meta_t meta;
    fd_backup_tar_file_hdr( &meta, sc_sz );
    fd_cstr_ncpy( meta.name, "snapshots/status_cache", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( ctx->raw, &meta, sizeof(fd_tar_meta_t) );
    ctx->raw_buf.size    = sizeof(fd_tar_meta_t);
    ctx->status_cache_pad = fd_ulong_align_up( sc_sz, 512UL ) - sc_sz;

    flush_buffer( ctx, ZSTD_e_continue );
    ctx->state = SNAPMK_STATE_STATUS_CACHE;
    break;
  }
  case SNAPMK_STATE_STATUS_CACHE: {
    if( FD_UNLIKELY( ctx->raw_buf.size + FD_TXNCACHE_WRITER_BUF_MIN > RAW_BUF_SZ ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      *charge_busy = 1;
      return;
    }
    ulong buf_rem  = RAW_BUF_SZ - ctx->raw_buf.size;
    ulong chunk_sz = fd_txncache_writer_serialize(
        ctx->txncache_writer,
        (uchar *)ctx->raw_buf.src + ctx->raw_buf.size,
        buf_rem );
    ctx->raw_buf.size += chunk_sz;
    if( FD_UNLIKELY( !chunk_sz ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      if( ctx->status_cache_pad ) {
        fd_memset( ctx->raw, 0, ctx->status_cache_pad );
        ctx->raw_buf.size = ctx->status_cache_pad;
      }
      flush_buffer( ctx, ZSTD_e_end );
      ctx->state = SNAPMK_STATE_EOF_MARKER;
    }
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_EOF_MARKER: {
    ctx->raw_buf.pos = 0UL;
    ctx->raw_buf.size = 1024UL;
    fd_memset( ctx->raw, 0, 1024UL );
    flush_buffer( ctx, ZSTD_e_end );

    struct stat st;
    if( FD_UNLIKELY( fstat( ctx->out_fd, &st ) ) ) {
      FD_LOG_ERR(( "fstat failed: %s", fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( close( ctx->out_fd ) ) ) {
      FD_LOG_ERR(( "close(%s) failed: %s", ctx->out_path, fd_io_strerror( errno ) ));
    }
    ctx->out_fd = -1;
    if( FD_UNLIKELY( renameat( ctx->snap_dir_fd, ctx->wip_name, ctx->snap_dir_fd, ctx->final_name ) ) ) {
      FD_LOG_ERR(( "renameat(%s, %s) failed: %s", ctx->wip_name, ctx->final_name, fd_io_strerror( errno ) ));
    }
    char final_path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( final_path, PATH_MAX, NULL, "%s/%s", ctx->snap_dir, ctx->final_name ) );

    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DONE, 0, 1, 0 );
    fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    resume_accdb_compaction( ctx );
    ctx->state = SNAPMK_STATE_IDLE;
    FD_LOG_NOTICE(( "Snapshot created in %.3f seconds (%s, %.3f GB)",
                    (double)( fd_log_wallclock() - ctx->start_time )/1e9,
                    final_path, (double)st.st_size/1e9 ));
    *charge_busy = 1;
    break;
  }
  default:
    FD_LOG_CRIT(( "invalid state %u", ctx->state ));
  }
}

static void
snap_begin( fd_snapmk_t * ctx,
            ulong         bank_idx ) {
  if( FD_UNLIKELY( ctx->state != SNAPMK_STATE_IDLE ) ) {
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
    return;
  }

  if( FD_UNLIKELY( ctx->out_fd!=-1 ) ) {
    if( FD_UNLIKELY( close( ctx->out_fd ) ) ) {
      FD_LOG_ERR(( "close(%s) failed: %s", ctx->out_path, fd_io_strerror( errno ) ));
    }
    ctx->out_fd = -1;
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_TEST( bank );
  ctx->bank = bank;

  uchar snap_hash[32];
  fd_blake3_hash( ctx->bank->f.lthash.bytes, FD_LTHASH_LEN_BYTES, snap_hash );
  char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( snap_hash, NULL, encoded_hash );
  FD_TEST( fd_cstr_printf_check( ctx->final_name, FD_BACKUP_NAME_MAX, NULL,
           "snapshot-%lu-%s.tar.zst", ctx->bank->f.slot, encoded_hash ) );
  FD_TEST( fd_cstr_printf_check( ctx->wip_name, FD_BACKUP_NAME_MAX, NULL, "%s.wip", ctx->final_name ) );
  FD_TEST( fd_cstr_printf_check( ctx->out_path, PATH_MAX, NULL, "%s/%s", ctx->snap_dir, ctx->wip_name ) );

  if( FD_UNLIKELY( unlinkat( ctx->snap_dir_fd, ctx->wip_name, 0 ) && errno!=ENOENT ) ) {
    FD_LOG_ERR(( "unlinkat(%s) failed: %s", ctx->wip_name, fd_io_strerror( errno ) ));
  }
  ctx->out_fd = openat( ctx->snap_dir_fd, ctx->wip_name, O_CREAT|O_EXCL|O_WRONLY, 0644 );
  if( FD_UNLIKELY( ctx->out_fd<0 ) ) {
    FD_LOG_ERR(( "openat(%s) failed: %s", ctx->wip_name, fd_io_strerror( errno ) ));
  }

  pause_accdb_compaction( ctx );

  *ctx->zp_file_off  = 0UL;
  ctx->raw_buf.size  = 0UL;
  ctx->raw_buf.pos   = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;

  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  fd_ssmanifest_writer_init( ctx->manifest_writer, bank );

  FD_COMPILER_MFENCE();
  ulong root_fork_id = __atomic_load_n( &ctx->accdb_root_fork->val, __ATOMIC_RELAXED );
  /* FIXME validate root_fork_id */
  ulong root_generation = __atomic_load_n( &ctx->accdb_shfork[ root_fork_id ].generation, __ATOMIC_RELAXED );
  FD_COMPILER_MFENCE();
  fd_backup_cache_reset( ctx->acc_cache, root_generation );
  visited_set_null( ctx->visited_set );

  ctx->state = SNAPMK_STATE_START;
  ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
  ctx->out_ready = 0UL;
  ctx->start_time = fd_log_wallclock();
  FD_MGAUGE_SET( SNAPMK, ACTIVE,            1UL );
  FD_MCNT_INC  ( SNAPMK, SNAPSHOTS_CREATED, 1UL );
  FD_LOG_NOTICE(( "Snapshot creation started" ));
}

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
  (void)seq; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  ctx->in_idle_cnt = 0UL;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    switch( sig ) {
    case REPLAY_SIG_SNAP_CREATE: {
      fd_replay_snap_create_t const * msg = fd_chunk_to_laddr_const( ctx->replay_in_mem, chunk );
      snap_begin( ctx, msg->bank_idx );
      break;
    }
    default:
      break;
    }
    break;
  default:
    FD_LOG_CRIT(( "unexpected msg from link %lu with sig %lu", in_idx, sig ));
  }
  return 0;
}

static void
metrics_write( fd_snapmk_t * ctx ) {
  FD_MGAUGE_SET( SNAPMK, ACTIVE,                      ctx->state!=SNAPMK_STATE_IDLE );
  FD_MCNT_SET(   SNAPMK, BYTES_COMPRESSED,            ctx->metrics.bytes_compressed );
  FD_MCNT_SET(   SNAPMK, BYTES_WRITTEN,               ctx->metrics.bytes_written    );
  FD_MCNT_SET(   SNAPMK, IO_BLOCKED_DURATION_SECONDS, ctx->metrics.io_ticks         );
  FD_MCNT_SET(   SNAPMK, COMPRESS_DURATION_SECONDS,   ctx->metrics.compress_ticks   );
}

#define STEM_BURST 1UL
#define STEM_LAZY  8700UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapmk_t)
#define STEM_CALLBACK_CHECK_CREDIT    check_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapmk = {
  .name                 = "snapmk",
  .populate_allowed_fds = populate_allowed_fds,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .privileged_init      = privileged_init,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .allow_renameat       = 1
};
