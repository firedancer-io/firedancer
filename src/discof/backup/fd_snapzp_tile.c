#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include "fd_backup.h"
#include "fd_backup_cache.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../tango/fseq/fd_fseq.h"
#include "../../util/pod/fd_pod.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

struct fd_snapzp {
  fd_backup_cache_t acc_cache[1];

  ZSTD_CCtx *    zst;
  uchar *        raw;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;

  ulong idle_cnt;

  ulong kind_id;
  ulong frame_id;
  fd_backup_frag_t * batch;

  int fd;
  int snap_dir_fd;
  ulong volatile * file_off;

  struct {
    ulong accounts_compressed;
    ulong bytes_compressed;
    ulong bytes_written;
    ulong io_blocked_ticks;
    ulong compress_ticks;
  } metrics;
};
typedef struct fd_snapzp fd_snapzp_t;

#define FD_ZSTD_LEVEL 1
#define RAW_BUF_SZ    (32UL<<20) /* FIXME make this configurable */
#define COMP_HEAD   522 /* raw tar header block */
#define COMP_BOUND  ZSTD_COMPRESSBOUND( RAW_BUF_SZ )
#define COMP_BUF_SZ FD_ULONG_ALIGN_UP( COMP_HEAD+COMP_BOUND+8UL, 4096UL )

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_SHMEM_HUGE_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapzp_t),  sizeof(fd_snapzp_t) );
  l = FD_LAYOUT_APPEND( l, 4096UL,                RAW_BUF_SZ          );
  l = FD_LAYOUT_APPEND( l, 4096UL,                COMP_BUF_SZ         );
  l = FD_LAYOUT_APPEND( l, 32UL,                  ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  return FD_LAYOUT_FINI( l, FD_SHMEM_HUGE_PAGE_SZ );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapzp_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  memset( ctx, 0, sizeof(fd_snapzp_t) );

  char snap_dir[ PATH_MAX ];
  fd_cstr_ncpy( snap_dir, tile->snapzp.out_path, PATH_MAX );
  char * last_slash = strrchr( snap_dir, '/' );
  if( FD_LIKELY( last_slash ) ) *last_slash = '\0';

  int dir_fd = open( snap_dir, O_RDONLY|O_DIRECTORY );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", snap_dir, fd_io_strerror( errno ) ));
  }
  ctx->snap_dir_fd = dir_fd;
  ctx->fd          = -1;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapzp_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  uchar *       raw_buf  = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,               RAW_BUF_SZ          );
  uchar *       comp_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,               COMP_BUF_SZ         );
  void *        _zstd    = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->zst = ZSTD_initStaticCStream( _zstd, ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_TEST( ctx->zst );
  ulong zst_err;
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_ZSTD_LEVEL );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableInBuffer, 1 );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_stableInBuffer=1) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_stableOutBuffer, 1 );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_stableOutBuffer=1) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->raw = raw_buf;
  ctx->raw_buf  = (ZSTD_inBuffer){ .src = raw_buf,  .size = 0UL };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = comp_buf+COMP_HEAD, .size = COMP_BUF_SZ-COMP_HEAD };

  FD_TEST( tile->in_cnt==1UL );
  FD_TEST( 0==strcmp( topo->links[ tile->in_link_id[0] ].name, "snapmk_zp" ) );
  ctx->batch = topo->links[ tile->in_link_id[0] ].dcache;

  ctx->kind_id = tile->kind_id;
  ctx->frame_id = 0UL;

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapzp.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  FD_TEST( fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro ) );

  ulong * zp_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapzp.zp_fseq_id ) ); FD_TEST( zp_fseq );
  ctx->file_off = fd_fseq_app_laddr( zp_fseq );
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapzp_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->snap_dir_fd;
  return out_cnt;
}

static void
before_credit( fd_snapzp_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem; (void)charge_busy;
  if( FD_UNLIKELY( ctx->idle_cnt++ > 65536UL ) ) {
    fd_log_sleep( (long)1e6 );
  }
}

static void
flush( fd_snapzp_t * ctx ) {
  /* Align input frame by 512 bytes */
  ulong content_usz = ctx->raw_buf.size;
  ulong content_asz = fd_ulong_align_up( content_usz, 512UL );
  if( content_asz > content_usz ) {
    FD_TEST( content_asz <= RAW_BUF_SZ );
    fd_memset( ctx->raw + content_usz, 0, content_asz - content_usz );
    ctx->raw_buf.size = content_asz;
  }

  /* Finish content compression frame */
  long t0 = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, ZSTD_e_end );
  ctx->metrics.bytes_compressed += ctx->raw_buf.pos;
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) failed: %s", ZSTD_getErrorName( ret ) ));
  }
  if( FD_UNLIKELY( ret!=0UL ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) did not finish frame" ));
  }
  long t1 = fd_tickcount();
  ctx->metrics.compress_ticks += (ulong)( t1 - t0 );
  FD_TEST( ctx->raw_buf.pos == ctx->raw_buf.size );
  ctx->raw_buf.pos  = 0UL;
  ctx->raw_buf.size = 0UL;

  /* Prepend compression frame with a TAR header */
  uchar * comp_head = (uchar *)ctx->comp_buf.dst - COMP_HEAD;
  memcpy( comp_head, (uchar[]){0x28,0xB5,0x2F,0xFD,0x60,0x00,0x01,0x01,0x10,0x00}, 10 );
  fd_tar_meta_t meta; fd_backup_tar_file_hdr( &meta, content_usz );
  /* Generate a unique file name */
  ulong frame_id = ctx->frame_id++;
  ulong vec_id   = (frame_id * SNAPZP_TILE_MAX) + ctx->kind_id;
  char * p = fd_cstr_init( meta.name );
  p = fd_cstr_append_cstr( p, "accounts/0." );
  p = fd_cstr_append_ulong_as_text( p, 0, 0, vec_id, fd_ulong_base10_dig_cnt( vec_id ) );
  fd_cstr_fini( p );
  fd_tar_meta_set_chksum( &meta );
  memcpy( comp_head+10, &meta, sizeof(fd_tar_meta_t) );

  /* Align to block size with a skippable frame */
  ulong comp_usz = COMP_HEAD + ctx->comp_buf.pos;
  ulong comp_asz = fd_ulong_align_up( comp_usz, 4096UL );
  ulong pad_sz   = comp_asz - comp_usz;
  if( FD_UNLIKELY( pad_sz>0UL && pad_sz<8UL ) ) {
    comp_asz += 4096UL;
    pad_sz   += 4096UL;
  }
  FD_TEST( comp_asz <= COMP_BUF_SZ );
  if( FD_LIKELY( pad_sz>0UL ) ) {
    uchar * tail = (uchar *)ctx->comp_buf.dst + ctx->comp_buf.pos;
    FD_STORE( uint, tail,   ZSTD_MAGIC_SKIPPABLE_START );
    FD_STORE( uint, tail+4, (uint)( pad_sz-8 ) );
    fd_memset( tail+8, 0, pad_sz-8 );
  }

  ulong off = __atomic_fetch_add( ctx->file_off, comp_asz, __ATOMIC_RELAXED );
  FD_TEST( fd_ulong_is_aligned( off,      4096UL ) );
  FD_TEST( fd_ulong_is_aligned( comp_asz, 4096UL ) );
  if( FD_UNLIKELY( pwrite( ctx->fd, comp_head, comp_asz, (long)off )!=(long)comp_asz ) ) {
    FD_LOG_ERR(( "pwrite failed: %i-%s", errno, fd_io_strerror( errno ) ));
  }
  long t2 = fd_tickcount();
  ctx->metrics.bytes_written    += comp_asz;
  ctx->metrics.io_blocked_ticks += (ulong)( t2 - t1 );

  ctx->comp_buf.pos = 0UL;
}

static void
process_start( fd_snapzp_t * ctx,
               ulong         seq ) {
  fd_backup_frag_t const * frag = ctx->batch + (seq & 31UL); /* FIXME depth mask hardcoded */
  ushort name_len = frag->start.name_len;
  if( FD_UNLIKELY( !name_len || name_len>=FD_BACKUP_NAME_MAX || frag->start.name[ name_len ] ) ) {
    FD_LOG_ERR(( "invalid snapshot file name length %hu", name_len ));
  }
  for( ushort i=0; i<name_len; i++ ) {
    if( FD_UNLIKELY( frag->start.name[ i ]=='/' ) ) {
      FD_LOG_ERR(( "invalid snapshot file name `%s`", frag->start.name ));
    }
  }

  if( FD_UNLIKELY( ctx->fd!=-1 ) ) {
    if( FD_UNLIKELY( close( ctx->fd ) ) ) {
      FD_LOG_ERR(( "close snapshot fd failed: %i-%s", errno, fd_io_strerror( errno ) ));
    }
    ctx->fd = -1;
  }
  ctx->fd = openat( ctx->snap_dir_fd, frag->start.name, O_WRONLY|O_DIRECT );
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "openat(%s) failed: %i-%s", frag->start.name, errno, fd_io_strerror( errno ) ));
  }

  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->frame_id      = 0UL;
  ctx->raw_buf.pos   = 0UL;
  ctx->raw_buf.size  = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ-COMP_HEAD;
}

static void
process_accounts_cached( fd_snapzp_t * ctx,
                         ulong         seq ) {
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "received account batch before snapshot start" ));
  }
  fd_backup_frag_t const * batch = ctx->batch + (seq & 31UL); /* FIXME depth mask hardcoded */
  ZSTD_inBuffer * buf = &ctx->raw_buf;
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    fd_pubkey_t const * pubkey  = &batch->acc_cache.pubkey [ i ];
    uint                acc_idx =  batch->acc_cache.acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;
    /* copy cached account into snapshot stream */
    int err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, buf, RAW_BUF_SZ );
    if( err==FD_BACKUP_CACHE_ERR_MISS ) continue; /* evicted */
    if( FD_UNLIKELY( err==FD_BACKUP_CACHE_ERR_SPACE ) ) {
      /* not enough buffer space, flush and retry */
      flush( ctx );
      err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, buf, RAW_BUF_SZ );
      if( err==FD_BACKUP_CACHE_ERR_MISS ) continue; /* evicted */
      FD_CHECK_ERR( err!=FD_BACKUP_CACHE_ERR_SPACE, "Zstandard buffer too small" );
    }
    FD_CHECK_ERR( err==FD_BACKUP_CACHE_SUCCESS, "unexpected cache error code" );
    ctx->metrics.accounts_compressed++;
  }
}

static int
returnable_frag( fd_snapzp_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx; (void)sig; (void)chunk; (void)sz; (void)tsorig; (void)tspub; (void)stem;
  ctx->idle_cnt = 0UL;
  ulong orig = fd_frag_meta_ctl_orig( ctl );
  switch( orig ) {
  case FD_BACKUP_ORIG_START:
    process_start( ctx, seq );
    break;
  case FD_BACKUP_ORIG_ACC_CACHE:
    process_accounts_cached( ctx, seq );
    break;
  case FD_BACKUP_ORIG_FLUSH:
    flush( ctx );
    break;
  case FD_BACKUP_ORIG_DONE:
    if( FD_UNLIKELY( ctx->fd!=-1 ) ) {
      if( FD_UNLIKELY( close( ctx->fd ) ) ) {
        FD_LOG_ERR(( "close snapshot fd failed: %i-%s", errno, fd_io_strerror( errno ) ));
      }
      ctx->fd = -1;
    }
    break;
  case FD_BACKUP_ORIG_RESET:
    ctx->frame_id = 0UL;
    break;
  default:
    FD_LOG_CRIT(( "unknown backup instruction (orig=%lu, seq=%lu)", orig, seq ));
  }
  return 0;
}

static void
metrics_write( fd_snapzp_t * ctx ) {
  FD_MCNT_SET( SNAPZP, ACCOUNTS_COMPRESSED,         ctx->metrics.accounts_compressed );
  FD_MCNT_SET( SNAPZP, BYTES_COMPRESSED,            ctx->metrics.bytes_compressed    );
  FD_MCNT_SET( SNAPZP, BYTES_WRITTEN,               ctx->metrics.bytes_written       );
  FD_MCNT_SET( SNAPZP, IO_BLOCKED_DURATION_SECONDS, ctx->metrics.io_blocked_ticks    );
  FD_MCNT_SET( SNAPZP, COMPRESS_DURATION_SECONDS,   ctx->metrics.compress_ticks      );
}

#define STEM_BURST 1UL
#define STEM_LAZY  9400UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapzp_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapzp_t)
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapzp = {
  .name                 = "snapzp",
  .populate_allowed_fds = populate_allowed_fds,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .privileged_init      = privileged_init,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .allow_renameat       = 1
};
