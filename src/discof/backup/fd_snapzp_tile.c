#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include "fd_backup.h"
#include "fd_backup_cache.h"
#include "fd_backup_visited.h"
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
  visited_set_t *   visited_set;

  ZSTD_CCtx *    zst;
  uchar *        raw;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;

  ulong idle_cnt;

  ulong kind_id;
  ulong frame_id;
  void *      snapmk_zp_mem;
  ulong       snapmk_zp_chunk0;
  ulong       snapmk_zp_wmark;
  fd_wksp_t *        snaprd_mem;

  int fd;
  int snap_dir_fd;
  ulong volatile * file_off;

  struct {
    int         active;
    fd_pubkey_t pubkey;
    fd_pubkey_t owner;
    uint        size;
    uint        acc_idx;
    ulong       data_rem;
    ulong       data_pad;
  } disk;

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

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "snapmk_zp" ) ) {
      ctx->snapmk_zp_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->snapmk_zp_chunk0 = fd_dcache_compact_chunk0( ctx->snapmk_zp_mem, link->dcache );
      ctx->snapmk_zp_wmark  = fd_dcache_compact_wmark ( ctx->snapmk_zp_mem, link->dcache, link->mtu );
    }
  }
  FD_TEST( ctx->snapmk_zp_mem );

  ulong snaprd_wksp_id = fd_topo_find_wksp( topo, "snaprd_out" );
  FD_TEST( snaprd_wksp_id!=ULONG_MAX );
  ctx->snaprd_mem = topo->workspaces[ snaprd_wksp_id ].wksp;
  FD_TEST( ctx->snaprd_mem );

  ctx->kind_id = tile->kind_id;
  ctx->frame_id = 0UL;
  memset( &ctx->disk, 0, sizeof(ctx->disk) );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapzp.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  FD_TEST( fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro ) );
  ctx->visited_set = visited_set_join( fd_topo_obj_laddr( topo, tile->snapzp.visited_set_obj_id ) );
  FD_TEST( ctx->visited_set );

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
               fd_backup_start_msg_t const * frag ) {
  ushort name_len = frag->name_len;
  if( FD_UNLIKELY( !name_len || name_len>=FD_BACKUP_NAME_MAX || frag->name[ name_len ] ) ) {
    FD_LOG_ERR(( "invalid snapshot file name length %hu", name_len ));
  }
  for( ushort i=0; i<name_len; i++ ) {
    if( FD_UNLIKELY( frag->name[ i ]=='/' ) ) {
      FD_LOG_ERR(( "invalid snapshot file name `%s`", frag->name ));
    }
  }

  if( FD_UNLIKELY( ctx->fd!=-1 ) ) {
    if( FD_UNLIKELY( close( ctx->fd ) ) ) {
      FD_LOG_ERR(( "close snapshot fd failed: %i-%s", errno, fd_io_strerror( errno ) ));
    }
    ctx->fd = -1;
  }
  ctx->fd = openat( ctx->snap_dir_fd, frag->name, O_WRONLY|O_DIRECT );
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "openat(%s) failed: %i-%s", frag->name, errno, fd_io_strerror( errno ) ));
  }

  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->frame_id      = 0UL;
  memset( &ctx->disk, 0, sizeof(ctx->disk) );
  ctx->raw_buf.pos   = 0UL;
  ctx->raw_buf.size  = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ-COMP_HEAD;
  ctx->metrics.accounts_compressed       = 0UL;
  ctx->metrics.bytes_compressed          = 0UL;
  ctx->metrics.bytes_written             = 0UL;
  ctx->metrics.io_blocked_ticks          = 0UL;
  ctx->metrics.compress_ticks            = 0UL;
}

static void
wait_disk_visible_and_clear_visited( fd_snapzp_t *       ctx,
                                     fd_pubkey_t const * pubkey,
                                     uint                acc_idx ) {
  (void)pubkey;
  if( FD_UNLIKELY( acc_idx==UINT_MAX || (ulong)acc_idx>=ctx->acc_cache->max_accounts ) ) {
    FD_LOG_ERR(( "invalid cache account index %u", acc_idx ));
  }

  fd_accdb_accmeta_t const * acc = &ctx->acc_cache->acc_pool[ acc_idx ];
  ulong off_packed = FD_VOLATILE_CONST( acc->offset_fork );
  while( FD_UNLIKELY( (off_packed & FD_ACCDB_OFF_MASK)==FD_ACCDB_OFF_INVAL ) ) {
    FD_SPIN_PAUSE();
    off_packed = FD_VOLATILE_CONST( acc->offset_fork );
  }

  FD_COMPILER_MFENCE();
  fd_backup_visited_remove( ctx->visited_set, (ulong)acc_idx );
}

static void
process_accounts_cached( fd_snapzp_t * ctx,
                         fd_backup_cache_msg_t const * batch ) {
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "received account batch before snapshot start" ));
  }
  ZSTD_inBuffer * buf = &ctx->raw_buf;
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    fd_pubkey_t const * pubkey  = &batch->pubkey [ i ];
    uint                acc_idx =  batch->acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;
    /* copy cached account into snapshot stream */
    int err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, buf, RAW_BUF_SZ );
    if( err==FD_BACKUP_CACHE_ERR_MISS ) {
      wait_disk_visible_and_clear_visited( ctx, pubkey, acc_idx );
      continue;
    }
    if( FD_UNLIKELY( err==FD_BACKUP_CACHE_ERR_SPACE ) ) {
      /* not enough buffer space, flush and retry */
      flush( ctx );
      err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, buf, RAW_BUF_SZ );
      if( err==FD_BACKUP_CACHE_ERR_MISS ) {
        wait_disk_visible_and_clear_visited( ctx, pubkey, acc_idx );
        continue;
      }
      FD_CHECK_ERR( err!=FD_BACKUP_CACHE_ERR_SPACE, "Zstandard buffer too small" );
    }
    FD_CHECK_ERR( err==FD_BACKUP_CACHE_SUCCESS, "unexpected cache error code" );
    ctx->metrics.accounts_compressed++;
  }
}

static fd_accdb_accmeta_t const *
find_disk_accmeta( fd_snapzp_t *       ctx,
                   fd_pubkey_t const * pubkey,
                   uint                size,
                   uint                acc_idx ) {
  fd_backup_cache_t * acc_cache = ctx->acc_cache;
  if( FD_UNLIKELY( acc_idx==UINT_MAX || (ulong)acc_idx>=acc_cache->max_accounts ) ) return NULL;

  fd_accdb_accmeta_t const * acc = &acc_cache->acc_pool[ acc_idx ];
  uint es = FD_VOLATILE_CONST( acc->executable_size );
  if( FD_UNLIKELY( FD_ACCDB_SIZE_DATA( es )!=FD_ACCDB_SIZE_DATA( size ) ) ) return NULL;
  if( FD_UNLIKELY( memcmp( acc->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) ) ) ) return NULL;
  return acc;
}

static ulong
begin_disk_account( fd_snapzp_t * ctx,
                    fd_backup_disk_msg_t const * frag,
                    ulong         sz ) {
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "received disk account before snapshot start" ));
  }
  if( FD_UNLIKELY( ctx->disk.active ) ) {
    FD_LOG_ERR(( "received account SOM while already processing a disk account" ));
  }
  if( FD_UNLIKELY( sz!=sizeof(fd_backup_disk_msg_t) ) ) {
    FD_LOG_ERR(( "invalid disk account control payload size (%lu != %lu)", sz, sizeof(fd_backup_disk_msg_t) ));
  }

  ulong data_len = (ulong)FD_ACCDB_SIZE_DATA( frag->size );
  ulong rec_sz   = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_len, 8UL );
  if( FD_UNLIKELY( rec_sz>RAW_BUF_SZ ) ) {
    FD_LOG_ERR(( "snapshot account record too large (%lu bytes)", rec_sz ));
  }
  if( FD_UNLIKELY( frag->snap_sz!=(uint)rec_sz ) ) {
    FD_LOG_ERR(( "disk account snapshot size hint mismatch (%u != %lu)", frag->snap_sz, rec_sz ));
  }
  if( FD_UNLIKELY( ctx->raw_buf.size + rec_sz > RAW_BUF_SZ ) ) flush( ctx );

  memset( &ctx->disk, 0, sizeof(ctx->disk) );
  ctx->disk.active  = 1;
  ctx->disk.pubkey  = frag->pubkey;
  ctx->disk.owner   = frag->owner;
  ctx->disk.size    = frag->size;
  ctx->disk.acc_idx = frag->acc_idx;

  fd_accdb_accmeta_t const * accmeta = find_disk_accmeta( ctx, &ctx->disk.pubkey, ctx->disk.size, ctx->disk.acc_idx );
  if( FD_UNLIKELY( !accmeta ) ) {
    FD_LOG_ERR(( "disk account not found in account index" ));
  }

  snap_acc_hdr_t * hdr = (snap_acc_hdr_t *)( (ulong)ctx->raw_buf.src + ctx->raw_buf.size );
  memset( hdr, 0, sizeof(snap_acc_hdr_t) );
  hdr->pubkey    = ctx->disk.pubkey;
  hdr->owner     = ctx->disk.owner;
  hdr->lamports   = FD_VOLATILE_CONST( accmeta->lamports );
  hdr->executable = !!FD_ACCDB_SIZE_EXEC( FD_VOLATILE_CONST( accmeta->executable_size ) );
  hdr->data_len   = data_len;

  ctx->raw_buf.size += sizeof(snap_acc_hdr_t);
  ctx->disk.data_rem = data_len;
  ctx->disk.data_pad = fd_ulong_align_up( data_len, 8UL ) - data_len;
  return (ulong)frag->data_sz;
}

static void
process_account_disk( fd_snapzp_t * ctx,
                      ulong         seq,
                      ulong         sig,
                      ulong         chunk,
                      ulong         sz,
                      ulong         ctl,
                      ulong         tsorig,
                      ulong         tspub ) {
  (void)seq; (void)tsorig;
  int som = fd_frag_meta_ctl_som( ctl );
  int eom = fd_frag_meta_ctl_eom( ctl );

  ulong frag_sz = tspub;
  if( FD_UNLIKELY( som ) ) {
    if( FD_UNLIKELY( sz!=sizeof(fd_backup_disk_msg_t) || chunk<ctx->snapmk_zp_chunk0 || chunk>ctx->snapmk_zp_wmark ) ) {
      FD_LOG_ERR(( "invalid ACC_DISK payload chunk=%lu sz=%lu", chunk, sz ));
    }
    fd_backup_disk_msg_t const * frag = fd_chunk_to_laddr_const( ctx->snapmk_zp_mem, chunk );
    frag_sz = begin_disk_account( ctx, frag, sz );
    if( FD_UNLIKELY( tspub!=frag_sz ) ) {
      FD_LOG_ERR(( "disk account data size mismatch (%lu != %lu)", tspub, frag_sz ));
    }
  } else if( FD_UNLIKELY( sz ) ) {
    FD_LOG_ERR(( "unexpected disk account payload on non-SOM fragment" ));
  }
  if( FD_UNLIKELY( !ctx->disk.active ) ) {
    FD_LOG_ERR(( "received disk account fragment without SOM" ));
  }

  uchar const * frag = NULL;
  if( FD_LIKELY( ctx->disk.data_rem ) ) {
    frag    = fd_wksp_laddr_fast( ctx->snaprd_mem, sig );
  }

  ulong take = fd_ulong_min( ctx->disk.data_rem, frag_sz );
  if( FD_LIKELY( take ) ) {
    FD_TEST( ctx->raw_buf.size + take <= RAW_BUF_SZ );
    fd_memcpy( (uchar *)ctx->raw_buf.src + ctx->raw_buf.size, frag, take );
    ctx->raw_buf.size  += take;
    ctx->disk.data_rem -= take;
    frag_sz            -= take;
  }
  if( FD_UNLIKELY( frag_sz ) ) {
    FD_LOG_ERR(( "disk account fragment has trailing bytes" ));
  }
  if( FD_UNLIKELY( !ctx->disk.data_rem && !eom ) ) {
    FD_LOG_ERR(( "disk account data completed before EOM" ));
  }

  if( FD_UNLIKELY( eom ) ) {
    if( FD_UNLIKELY( ctx->disk.data_rem ) ) {
      FD_LOG_ERR(( "disk account ended before expected record size" ));
    }
    if( ctx->disk.data_pad ) {
      FD_TEST( ctx->raw_buf.size + ctx->disk.data_pad <= RAW_BUF_SZ );
      fd_memset( (uchar *)ctx->raw_buf.src + ctx->raw_buf.size, 0, ctx->disk.data_pad );
      ctx->raw_buf.size += ctx->disk.data_pad;
    }
    memset( &ctx->disk, 0, sizeof(ctx->disk) );
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
  (void)in_idx; (void)stem;
  ctx->idle_cnt = 0UL;
  ulong orig = fd_frag_meta_ctl_orig( ctl );
  switch( orig ) {
  case FD_BACKUP_ORIG_START: {
    if( FD_UNLIKELY( sz!=sizeof(fd_backup_start_msg_t) || chunk<ctx->snapmk_zp_chunk0 || chunk>ctx->snapmk_zp_wmark ) ) {
      FD_LOG_ERR(( "invalid START payload chunk=%lu sz=%lu", chunk, sz ));
    }
    fd_backup_start_msg_t const * frag = fd_chunk_to_laddr_const( ctx->snapmk_zp_mem, chunk );
    process_start( ctx, frag );
    break;
  }
  case FD_BACKUP_ORIG_ACC_CACHE: {
    if( FD_UNLIKELY( sz!=sizeof(fd_backup_cache_msg_t) || chunk<ctx->snapmk_zp_chunk0 || chunk>ctx->snapmk_zp_wmark ) ) {
      FD_LOG_ERR(( "invalid ACC_CACHE payload chunk=%lu sz=%lu", chunk, sz ));
    }
    fd_backup_cache_msg_t const * frag = fd_chunk_to_laddr_const( ctx->snapmk_zp_mem, chunk );
    process_accounts_cached( ctx, frag );
    break;
  }
  case FD_BACKUP_ORIG_ACC_DISK:
    process_account_disk( ctx, seq, sig, chunk, sz, ctl, tsorig, tspub );
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
