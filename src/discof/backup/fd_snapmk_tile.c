#define _GNU_SOURCE
#include "fd_snapmk.h"
#include "fd_ssmanifest_writer.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define FD_ZSTD_LEVEL 1
#define RAW_BUF_SZ    (32UL<<20)
#define COMP_BUF_SZ   ZSTD_COMPRESSBOUND( RAW_BUF_SZ )

/* Funk rooted record iterator (thread-safe) */

struct fd_snapmk {
  fd_funk_t funk[1];

  uint state;
  fd_funk_scan_t scan[1];

  ulong zp_cnt; /* [0,zp_cnt] out links are to zp */
  ulong out_meta_idx;

  ulong out_ready;         /* bit set */
  ulong out_flush_pending; /* bit set */

  int              out_fd;
  ulong volatile * zp_file_off;
  ulong            in_idle_cnt;

  ulong chain;
  ulong chain1;

  fd_snapmk_batch_t * batch  [ FD_TOPO_MAX_TILE_OUT_LINKS ];
  ushort              in_kind[ FD_TOPO_MAX_TILE_IN_LINKS  ];

  fd_banks_t *           banks;
  fd_bank_t const *      bank;
  fd_wksp_t *            replay_in_mem;
  fd_ssmanifest_writer_t manifest_writer[1];
  ulong                  manifest_pad;

  ZSTD_CCtx *    zst;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;

  uchar raw [ RAW_BUF_SZ  ];
  uchar comp[ COMP_BUF_SZ ];

  struct {
    ulong compress_ticks;
    ulong io_ticks;
    ulong bytes_compressed;
    ulong metrics_written;
  } metrics;
};
typedef struct fd_snapmk fd_snapmk_t;

#define IN_KIND_REPLAY 1

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_SHMEM_HUGE_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  l = FD_LAYOUT_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  return FD_LAYOUT_FINI( l, FD_SHMEM_HUGE_PAGE_SZ );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  char const * out_path = "/data/r/firedancer/snapout.zst";
  int fd = open( out_path, O_CREAT|O_WRONLY, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", out_path, fd_io_strerror( errno ) ));
  }
  ctx->out_fd = fd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapmk_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t)                       );
  void *        _zstd = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->state = SNAPMK_STATE_IDLE;

  ulong funk_obj_id;  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ) )!=ULONG_MAX );
  ulong locks_obj_id; FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ) ) );

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  ulong * zp_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.zp_fseq_id ) ); FD_TEST( zp_fseq );
  ctx->zp_file_off = fd_fseq_app_laddr( zp_fseq );

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
    ctx->batch[ i ] = link->dcache;
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

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->out_fd;
  return out_cnt;
}

/* Output stream format
   - snapmk produces multiple independent byte streams of uncompressed
     snapshot data
   - each stream is an unterminated .tar stream (no 512-byte EOF record)
   - each stream is sent to a snapzp tile (for compression and writing)
   - output streams are chopped up into fragment sequences and sent over
     tango (mcache/dcache)
   - each frag sequence begins with ctl.som=1 and ends with ctl.eom=1
   - a frag sequence is aligned to tar stream boundaries
   - each frag carries up to 2^16 bytes data

   Output stream logic
   - uses dcache allocators
   - links are reliable
   - backpressure on each link is tracked separately
   - each produce burst can create multiple frags
   - when an output link is backpressured, switches to the next
   - links are prioritized by index (link 0 has highest priority) */

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
  case SNAPMK_STATE_ACCOUNTS:
    *is_backpressured = 0;
    if( FD_UNLIKELY( !ctx->out_ready ) ) {
      update_flow_control( ctx, stem );
      if( FD_UNLIKELY( !ctx->out_ready ) ) {
        *is_backpressured = 1;
        return;
      }
    }
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH:
    /* Block until all zp tiles are caught up */
    if( !all_out_links_caught_up( ctx, stem ) ) {
      *is_backpressured = 1;
      return;
    }
    /* Send a flush packet */
    *is_backpressured = 0;
    *charge_busy      = 1;
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
  case SNAPMK_STATE_TAR_HEADERS: {
    ulong slot = ctx->bank->f.slot;

    ctx->raw_buf.pos = ctx->raw_buf.size = 0UL;
    uchar * p = ctx->raw;
    fd_tar_meta_t meta;

    fd_snapmk_tar_file_hdr( &meta, 5UL );
    fd_cstr_ncpy( meta.name, "version", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    memcpy( p,   "1.2.0",       5UL );
    memset( p+5, 0,       512UL-5UL );
    p += 512UL;

    fd_snapmk_tar_dir_hdr( &meta );
    fd_cstr_ncpy( meta.name, "snapshots/", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    fd_snapmk_tar_dir_hdr( &meta );
    fd_cstr_printf_check( meta.name, sizeof(meta.name), NULL, "snapshots/%lu/", slot );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    ulong manifest_sz = fd_snap_manifest_serialized_sz( ctx->bank );
    fd_snapmk_tar_file_hdr( &meta, manifest_sz );
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
    ulong buf_rem = FD_SSMANIFEST_BUF_MIN - ctx->raw_buf.size;
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
      ctx->state = SNAPMK_STATE_ACCOUNTS;
      align_stream( ctx );
      *charge_busy = 1;
      return;
    }
    break;
  }
  case SNAPMK_STATE_ACCOUNTS: {
    int out_idx = fd_ulong_find_lsb( ctx->out_ready );
    ulong seq = stem->seqs[ out_idx ];
    ctx->scan->batch = ctx->batch[ out_idx ] + (seq & (stem->depths[ out_idx ]-1));
    fd_funk_scan_refill( ctx->scan, ctx->chain );
    ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_BATCH, 0, 0, 0 );
    fd_stem_publish( stem, (ulong)out_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    _Bool blocked = !stem->cr_avail[ out_idx ];
    ctx->out_ready &= blocked ? ~fd_ulong_mask_bit( out_idx ) : ULONG_MAX;
    ctx->chain += FUNK_SCAN_PARA;
    if( FD_UNLIKELY( ctx->chain >= ctx->chain1 ) ) {
      FD_LOG_NOTICE(( "Done compressing accounts, waiting for I/O" ));
      ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH;
      ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
      break;
    }
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_FLUSH: {
    /* Broadcast FLUSH packets */
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_FLUSH, 0, 0, 0 );
      fd_stem_publish( stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
    }
    if( !ctx->out_flush_pending ) {
      ulong ctl = fd_frag_meta_ctl( SNAPMK_ORIG_DONE, 0, 1, 0 );
      fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->state = SNAPMK_STATE_IDLE;
      FD_LOG_NOTICE(( "Snapshot creation finished" ));
    }
    break;
  }
  }
}

static void
snap_begin( fd_snapmk_t * ctx,
            ulong         bank_idx ) {
  if( FD_UNLIKELY( ctx->state != SNAPMK_STATE_IDLE ) ) {
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
    return;
  }
  if( FD_UNLIKELY( ftruncate( ctx->out_fd, 0 ) ) ) {
    FD_LOG_ERR(( "ftruncate failed: %s", fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( lseek( ctx->out_fd, 0, SEEK_SET )<0 ) ) {
    FD_LOG_ERR(( "lseek failed: %s", fd_io_strerror( errno ) ));
  }
  *ctx->zp_file_off  = 0UL;
  ctx->raw_buf.size  = 0UL;
  ctx->raw_buf.pos   = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;

  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_TEST( bank );
  ctx->bank = bank;
  fd_ssmanifest_writer_init( ctx->manifest_writer, bank );

  ctx->state = SNAPMK_STATE_TAR_HEADERS;
  ctx->chain = 0UL;
  ctx->chain1 = fd_ulong_align_dn( fd_funk_rec_map_chain_cnt( ctx->funk->rec_map ), FUNK_SCAN_PARA );
  fd_funk_scan_init( ctx->scan, ctx->funk );
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
  FD_MGAUGE_SET( SNAPMK, ACTIVE, ctx->state!=SNAPMK_STATE_IDLE );
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
  .name                     = "snapmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
