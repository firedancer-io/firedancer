/* The snapzp tile gathers account data, compresses it, and writes it to
   disk.

   It has two modes:
   - cache: resolve account pointers from in-memory DB cache (fall back
            to disk on overrun)
   - disk:  recover accounts from streaming disk reads (from snaprd)

   Internally, snapzp does streaming compression from DRAM into tile
   scratch memory.  Whenever compression scratch buffer fills, it is
   prepended on-the-fly with a matching compressed TAR header.  Finally,
   everything is written to disk. */

#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include "fd_backup.h"
#include "fd_backup_cache.h"
#include "fd_backup_visited.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"

#include <time.h> /* CLOCK_REALTIME */
#include "generated/fd_snapzp_tile_seccomp.h"
#include "../../tango/fseq/fd_fseq.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define FD_ZSTD_LEVEL 1

/* Compression buffer params */
#define RAW_BUF_SZ    (32UL<<20) /* FIXME make this configurable */
#define COMP_BOUND    ZSTD_COMPRESSBOUND( RAW_BUF_SZ )
#define COMP_HEAD     522 /* 10 byte Zstandard uncompressed header + 512 byte plaintext tar header */
#define COMP_BUF_SZ   FD_ULONG_ALIGN_UP( COMP_HEAD+COMP_BOUND+8UL, 4096UL )

struct fd_snapzp {
  fd_backup_cache_t  acc_cache[1];
  visited_set_t *    visited_set;
  fd_accdb_t *       accdb;
  fd_accdb_fork_id_t fork_id;

  /* compression buffer */
  ZSTD_CCtx *    zst;
  ulong          zst_in_rec; /* ZSTD_CStreamInSize() */
  uchar *        raw;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;

  ulong idle_cnt;

  ulong kind_id;  /* index of this tile kind */
  ulong frame_id; /* sequence number for tar file names */
  ulong snapshot_slot;

  /* input link */
  void * snapmk_zp_mem;
  ulong  snapmk_zp_chunk0;
  ulong  snapmk_zp_wmark;
  void * snaprd_mem;
  ulong  snaprd_data0;
  ulong  snaprd_data1;

  /* snapshot files (all O_DIRECT write-only seekable) */
  int   snap_fd;      /* current snap being written */
  ulong snap_fd_cnt;  /* open snap fd count (see FD_SNAP_DIO_FD) */

  /* bump allocator for file offsets used to coordinate snapzp take
     turns to write to a file.  512 byte aligned for direct I/O. */
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

  __attribute__((aligned(4096))) uchar raw_buf1 [ RAW_BUF_SZ  ];
  __attribute__((aligned(4096))) uchar comp_buf1[ COMP_BUF_SZ ];
};
typedef struct fd_snapzp fd_snapzp_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_SHMEM_HUGE_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),     fd_accdb_footprint( tile->snapzp.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  return FD_LAYOUT_FINI( l, FD_SHMEM_HUGE_PAGE_SZ );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  (void)topo;
  ulong snap_fd_max = tile->snapzp.snap_fd_cnt;
  FD_CHECK_ERR( snap_fd_max>0UL && snap_fd_max<=FD_SNAP_MAX,
                "invalid snap_fd_max" );
  for( uint i=0U; i<snap_fd_max; i++ ) {
    if( FD_UNLIKELY( -1==fcntl( FD_SNAP_DIO_FD( i ), F_GETFD ) ) )
      FD_LOG_ERR(( "fcntl(snapshot pool fd %d) failed (%i-%s), was the snapshot pool initialized on boot?",
                   FD_SNAP_DIO_FD( i ), errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_CHECK_ERR( tile->kind_id < SNAPZP_TILE_MAX, "too many snapzp tiles" );

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapzp_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  void *        _accdb   = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),     fd_accdb_footprint( tile->snapzp.max_live_slots ) );
  void *        _zstd    = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  memset( ctx, 0, sizeof(fd_snapzp_t) );  /* 64 MiB-ish memset */
  ctx->snap_fd_cnt = tile->snapzp.snap_fd_cnt;
  ctx->snap_fd     = -1;

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
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_srcSizeHint, (int)RAW_BUF_SZ );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_srcSizeHint) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->zst_in_rec = ZSTD_CStreamInSize();
  ctx->raw      = ctx->raw_buf1;
  ctx->raw_buf  = (ZSTD_inBuffer ){ .src = ctx->raw_buf1, .size = 0UL };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = ctx->comp_buf1+COMP_HEAD, .size = COMP_BUF_SZ-COMP_HEAD };

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "snapmk_zp" ) ) {
      ctx->snapmk_zp_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->snapmk_zp_chunk0 = fd_dcache_compact_chunk0( ctx->snapmk_zp_mem, link->dcache );
      ctx->snapmk_zp_wmark  = fd_dcache_compact_wmark ( ctx->snapmk_zp_mem, link->dcache, link->mtu );
    }
  }
  FD_TEST( ctx->snapmk_zp_mem );

  /* discover snaprd_out link */
  ulong snaprd_wksp_id = fd_topo_find_wksp( topo, "snaprd_out" );
  FD_CHECK_ERR( snaprd_wksp_id!=ULONG_MAX, "snapzp tile not joined to snaprd_out wksp" );
  ulong snaprd_link_id = fd_topo_find_link( topo, "snaprd_out", 0UL );
  FD_CHECK_ERR( snaprd_link_id!=ULONG_MAX, "snaprd_out:0: link not found" );
  ulong snaprd_dcache_id = topo->links[ snaprd_link_id ].dcache_obj_id;
  FD_CHECK_ERR( snaprd_dcache_id!=ULONG_MAX, "snaprd_out:0: dcache_obj_id not found" );
  FD_CHECK_ERR( topo->objs[ snaprd_dcache_id ].wksp_id==snaprd_wksp_id, "snaprd_out:0: dcache_obj_id not in snaprd_out wksp" );
  uchar const * dcache = topo->links[ snaprd_link_id ].dcache;
  FD_CHECK_ERR( dcache, "snaprd_out:0: dcache pointer is NULL" );
  ctx->snaprd_data0 = (ulong)dcache;
  ctx->snaprd_data1 = (ulong)dcache + fd_dcache_data_sz( dcache );

  ctx->snaprd_mem = topo->workspaces[ snaprd_wksp_id ].wksp;
  FD_TEST( ctx->snaprd_mem );

  ctx->kind_id = tile->kind_id;
  ctx->frame_id = 0UL;
  memset( &ctx->disk, 0, sizeof(ctx->disk) );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapzp.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapzp.accdb_epoch_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb = fd_accdb_join_readonly( _accdb, accdb_shmem_ro, epoch_fseq, FD_ACCDB_FD_RO );
  FD_TEST( ctx->accdb );
  FD_TEST( fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro, epoch_fseq ) );
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
  (void)topo;
  ulong snap_fd_cnt = tile->snapzp.snap_fd_cnt;
  FD_CHECK_ERR( out_fds_cnt>=3UL+snap_fd_cnt, "out_fds[] too small" );
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO;
  for( uint i=0U; i<snap_fd_cnt; i++ )
    out_fds[ out_cnt++ ] = FD_SNAP_DIO_FD( i );
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  ulong snap_fd_cnt = tile->snapzp.snap_fd_cnt;
  populate_sock_filter_policy_fd_snapzp_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)FD_SNAP_DIO_FD( 0 ),
      (uint)FD_SNAP_DIO_FD( snap_fd_cnt-1U ),
      (uint)FD_ACCDB_FD_RO );
  return sock_filter_policy_fd_snapzp_tile_instr_cnt;
}

static void
before_credit( fd_snapzp_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem; (void)charge_busy;
  if( FD_LIKELY( ctx->snap_fd>=0 ) ) {
    /* Don't sleep while snapshot production is active
       FIXME this is quite wasteful */
    ctx->idle_cnt = 0UL;
    return;
  }
  if( FD_UNLIKELY( ctx->idle_cnt++ > 16384UL ) ) {
    fd_log_sleep( (long)1e6 );
  }
}

/* msg_start is called on all snapzp tiles before snapshot production
   starts. */

static void
msg_start( fd_snapzp_t *                 ctx,
           fd_backup_start_msg_t const * frag ) {
  FD_CHECK_CRIT( frag->snap_idx < ctx->snap_fd_cnt, "invalid snapshot pool slot" );
  ctx->snap_fd       = FD_SNAP_DIO_FD( frag->snap_idx );
  ctx->fork_id       = (fd_accdb_fork_id_t){ .val = frag->fork_id };
  ctx->snapshot_slot = frag->slot;

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
}

/* zip_work does opportunistic Zstandard compression work in memory.
   This function is tuned for a good tradeoff between latency
   (contiguous busy cycles) and throughput (dispatch overhead of libzstd
   function calls). */

static void
zip_work( fd_snapzp_t * ctx ) {
  if( FD_LIKELY( ctx->raw_buf.size - ctx->raw_buf.pos < ctx->zst_in_rec ) ) return;
  ulong raw_pos = ctx->raw_buf.pos;
  long  t0      = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, ZSTD_e_continue );
  long  t1  = fd_tickcount();
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_continue) failed: %s", ZSTD_getErrorName( ret ) ));
  }
  ctx->metrics.bytes_compressed += ctx->raw_buf.pos - raw_pos;
  ctx->metrics.compress_ticks   += (ulong)( t1-t0 );
}

/* zip_flush ends the current Zstandard compression frame and does a
   blocking direct I/O write.  Both uncompressed and compressed streams
   are padded up to 512 byte alignment to meet TAR and direct I/O
   requirements respectively. */

static void
zip_flush( fd_snapzp_t * ctx ) {
  FD_CHECK_CRIT( !ctx->disk.active, "attempted to flush with active defrag op" );

  /* Align input frame by 512 bytes (TAR file format) */
  ulong content_usz = ctx->raw_buf.size;
  ulong content_asz = fd_ulong_align_up( content_usz, 512UL );
  if( content_asz > content_usz ) {
    FD_TEST( content_asz <= RAW_BUF_SZ );
    fd_memset( ctx->raw + content_usz, 0, content_asz - content_usz );
    ctx->raw_buf.size = content_asz;
  }

  /* Finish content compression frame */
  ulong raw_pos = ctx->raw_buf.pos;
  long  t0      = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, ZSTD_e_end );
  long  t1  = fd_tickcount();
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) failed: %s", ZSTD_getErrorName( ret ) ));
  }
  if( FD_UNLIKELY( ret!=0UL ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) did not finish frame" ));
  }
  ctx->metrics.bytes_compressed += ctx->raw_buf.pos - raw_pos;
  ctx->metrics.compress_ticks   += (ulong)( t1-t0 );
  FD_TEST( ctx->raw_buf.pos == ctx->raw_buf.size );
  ctx->raw_buf.pos  = 0UL;
  ctx->raw_buf.size = 0UL;

  /* Prepend compression frame with a TAR header
     (Zstandard frame with a 512 byte uncompressed block) */
  uchar * comp_head = (uchar *)ctx->comp_buf.dst - COMP_HEAD;
  memcpy( comp_head, (uchar[]){0x28,0xB5,0x2F,0xFD,0x60,0x00,0x01,0x01,0x10,0x00}, 10 );
  fd_tar_meta_t meta; fd_backup_tar_file_hdr( &meta, content_usz );

  /* Generate a unique file name */
  ulong frame_id = ctx->frame_id++;
  ulong vec_id   = (frame_id * SNAPZP_TILE_MAX) + ctx->kind_id;
  do {
    ulong slot = ctx->snapshot_slot;
    char * p = fd_cstr_init( meta.name );
    p = fd_cstr_append_cstr( p, "accounts/" );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, slot,   fd_ulong_base10_dig_cnt( slot   ) );
    p = fd_cstr_append_char( p, '.' );
    p = fd_cstr_append_ulong_as_text( p, 0, 0, vec_id, fd_ulong_base10_dig_cnt( vec_id ) );
    fd_cstr_fini( p );
  } while(0);
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

  /* Allocate file range to write into */
  ulong off = __atomic_fetch_add( ctx->file_off, comp_asz, __ATOMIC_RELAXED );
  FD_TEST( fd_ulong_is_aligned( off,      4096UL ) );
  FD_TEST( fd_ulong_is_aligned( comp_asz, 4096UL ) );
  t0 = fd_tickcount();
  long write_sz = pwrite( ctx->snap_fd, comp_head, comp_asz, (long)off );
  t1 = fd_tickcount();
  if( FD_UNLIKELY( write_sz!=(long)comp_asz ) ) {
    FD_LOG_ERR(( "pwrite failed: %i-%s", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.bytes_written    += comp_asz;
  ctx->metrics.io_blocked_ticks += (ulong)( t1-t0 );

  /* Free compressed buffer */
  ctx->comp_buf.pos = 0UL;
}

/* accmeta_await_evict waits until the account data belonging to the
   given index entry is evicted from cache to disk.  This is used to
   fallback to disk reads when a cache read is torn by eviction. */

static void
accmeta_await_evict( fd_snapzp_t * ctx,
                     uint          acc_idx ) {
  fd_backup_accidx_t * idx = &ctx->acc_cache->idx;
  FD_CHECK_CRIT( fd_backup_accidx_valid( idx, acc_idx ), "invalid account index" );

  fd_accdb_accmeta_t const * acc = &idx->acc_pool[ acc_idx ];
  for(;;) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *idx->epoch_slot ) = FD_VOLATILE_CONST( *idx->epoch );
    FD_HW_MFENCE();

    ulong off_packed = FD_VOLATILE_CONST( acc->offset_fork );
    int   done       = ( off_packed & FD_ACCDB_OFF_MASK )!=FD_ACCDB_OFF_INVAL;

    FD_COMPILER_MFENCE();
    FD_VOLATILE( *idx->epoch_slot ) = ULONG_MAX;

    if( FD_LIKELY( done ) ) break;
    FD_SPIN_PAUSE(); /* FIXME yield to OS instead? */
  }

  FD_COMPILER_MFENCE();
  fd_backup_visited_remove( ctx->visited_set, (ulong)acc_idx );
}

/* msg_acc_cache instructs snapzp to gather, compress, and write out a
   bunch of accounts in cache.  Note that accdb cache entries are not
   pinned.  Account cache data can be evicted during read, leading to
   use-after-free, which this function gracefully recovers from. */

static void
msg_acc_cache( fd_snapzp_t *                 ctx,
               fd_backup_cache_msg_t const * batch ) {
  FD_CHECK_CRIT( ctx->snap_fd>=0, "invalid snapshot file descriptor" );

  fd_backup_accidx_t * idx      = &ctx->acc_cache->idx;
  int                  in_epoch = 0;

  ZSTD_inBuffer * buf = &ctx->raw_buf;
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    fd_pubkey_t const * pubkey  = &batch->pubkey [ i ];
    uint                acc_idx =  batch->acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;

    if( FD_UNLIKELY( !in_epoch ) ) {
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *idx->epoch_slot ) = FD_VOLATILE_CONST( *idx->epoch );
      /* a lock prefix is an expensive CPU pipeline hazard, therefore
         we hold onto our epoch for multiple accounts */
      FD_HW_MFENCE();
      in_epoch = 1;
    }

    int err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, ctx->raw, &buf->size, RAW_BUF_SZ );
    if( FD_UNLIKELY( err==FD_BACKUP_CACHE_ERR_SPACE ) ) {
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *idx->epoch_slot ) = ULONG_MAX;
      zip_flush( ctx );
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *idx->epoch_slot ) = FD_VOLATILE_CONST( *idx->epoch );
      FD_HW_MFENCE();
      err = fd_backup_cache_read( ctx->acc_cache, pubkey, acc_idx, ctx->raw, &buf->size, RAW_BUF_SZ );
      FD_CHECK_ERR( err!=FD_BACKUP_CACHE_ERR_SPACE, "Zstandard buffer too small" );
    }

    if( FD_UNLIKELY( err==FD_BACKUP_CACHE_ERR_MISS ) ) {
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *idx->epoch_slot ) = ULONG_MAX;
      in_epoch = 0;
      accmeta_await_evict( ctx, acc_idx );
      continue;
    }
    FD_CHECK_ERR( err==FD_BACKUP_CACHE_SUCCESS, "unexpected cache error code" );
    ctx->metrics.accounts_compressed++;
  }

  if( FD_LIKELY( in_epoch ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *idx->epoch_slot ) = ULONG_MAX;
  }
}

static void
msg_acc_delta( fd_snapzp_t *                 ctx,
               fd_backup_delta_msg_t const * batch ) {
  FD_CHECK_CRIT( ctx->snap_fd>=0, "invalid snapshot file descriptor" );
  FD_CHECK_CRIT( !ctx->disk.active, "received account delta while already processing a disk account" );
  FD_CHECK_CRIT( batch->cnt<=FD_BACKUP_CACHE_PARA, "invalid delta account batch" );

  ulong const rec_max = sizeof(snap_acc_hdr_t) + FD_RUNTIME_ACC_SZ_MAX;
  FD_STATIC_ASSERT( sizeof(snap_acc_hdr_t)+FD_RUNTIME_ACC_SZ_MAX<=RAW_BUF_SZ, raw_buf_too_small );

  for( ulong i=0UL; i<(ulong)batch->cnt; i++ ) {
    if( FD_UNLIKELY( ctx->raw_buf.size + rec_max > RAW_BUF_SZ ) ) zip_flush( ctx );

    ulong            start = ctx->raw_buf.size;
    snap_acc_hdr_t * hdr   = (snap_acc_hdr_t *)( ctx->raw + start );
    memset( hdr, 0, sizeof(snap_acc_hdr_t) );
    hdr->pubkey = batch->pubkey[ i ];

    ulong lamports   = 0UL;
    ulong data_len   = 0UL;
    int   executable = 0;
    fd_accdb_read_one_nocache( ctx->accdb, ctx->fork_id, batch->pubkey[ i ].uc,
                               &lamports, &executable, hdr->owner.uc,
                               ctx->raw + start + sizeof(snap_acc_hdr_t), &data_len );
    FD_CHECK_CRIT( data_len<=FD_RUNTIME_ACC_SZ_MAX, "accdb returned oversized account" );
    hdr->lamports   = lamports;
    hdr->executable = (uchar)!!executable;
    hdr->data_len   = data_len;

    ulong data_pad = fd_ulong_align_up( data_len, 8UL ) - data_len;
    if( data_pad ) fd_memset( ctx->raw + start + sizeof(snap_acc_hdr_t) + data_len, 0, data_pad );
    ctx->raw_buf.size = start + sizeof(snap_acc_hdr_t) + data_len + data_pad;
    ctx->metrics.accounts_compressed++;
  }
}

/* accmeta_disk validates that an index entry (at acc_idx with given
   pubkey) is an on-disk rooted account.
   (Safe while compaction and rooting are disabled, as on-disk rooted
   accounts are pinned in the index and on-disk under these conditions.

   Returns a pointer to the index entry if a matching record is found,
   NULL otherwise.  (Never returns NULL under correct usage.) */

static fd_accdb_accmeta_t const *
accmeta_disk( fd_snapzp_t *       ctx,
              fd_pubkey_t const * pubkey,
              uint                size,
              uint                acc_idx ) {
  fd_backup_accidx_t const * idx = &ctx->acc_cache->idx;
  if( FD_UNLIKELY( !fd_backup_accidx_valid( idx, acc_idx ) ) ) return NULL;

  fd_accdb_accmeta_t const * acc = &idx->acc_pool[ acc_idx ];
  uint es = FD_VOLATILE_CONST( acc->executable_size );
  if( FD_UNLIKELY( FD_ACCDB_SIZE_DATA( es )!=FD_ACCDB_SIZE_DATA( size ) ) ) return NULL;
  if( FD_UNLIKELY( memcmp( acc->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) ) ) ) return NULL;
  return acc;
}

/* msg_acc_disk instructs snapzp to compress an account fragment that
   was read from the accdb disk file.  (slow path)

   The first fragment of an account has an associated backup_disk_msg
   descriptor (chunk serves as ptr, sz is the descriptor sz, i.e.
   sizeof(fd_backup_disk_msg_t)).  The first frag is indicated by the
   ctl.som flag.

   The remaining fragments do not have a descriptor.  The last frag is
   indicated by the ctl.eom frag.

   The account data fragment size is in tspub.

   msg_acc_disk_start is a helper function that starts a disk account
   defrag operation.  Returns the number of bytes consumed (always the
   frag data size). */

static ulong
msg_acc_disk_start( fd_snapzp_t *                ctx,
                    fd_backup_disk_msg_t const * frag ) {
  FD_CHECK_CRIT( ctx->snap_fd>=0, "invalid snapshot file descriptor" );
  FD_CHECK_CRIT( !ctx->disk.active, "received account SOM while already processing a disk account" );

  ulong data_len = (ulong)FD_ACCDB_SIZE_DATA( frag->size );
  ulong rec_sz   = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_len, 8UL );
  FD_CHECK_CRIT( rec_sz<=RAW_BUF_SZ, "oversize snapshot account record" );
  FD_CHECK_CRIT( frag->snap_sz==rec_sz, "disk account snapshot size mismatch" );
  if( FD_UNLIKELY( ctx->raw_buf.size + rec_sz > RAW_BUF_SZ ) ) {
    zip_flush( ctx );
  }

  memset( &ctx->disk, 0, sizeof(ctx->disk) );
  ctx->disk.active  = 1;
  ctx->disk.pubkey  = frag->pubkey;
  ctx->disk.owner   = frag->owner;
  ctx->disk.size    = frag->size;
  ctx->disk.acc_idx = frag->acc_idx;

  fd_accdb_accmeta_t const * accmeta = accmeta_disk( ctx, &ctx->disk.pubkey, ctx->disk.size, ctx->disk.acc_idx );
  FD_CHECK_CRIT( accmeta, "bug in snapshot producer: rooted account disappeared from index" );

  snap_acc_hdr_t * hdr = (snap_acc_hdr_t *)( ctx->raw + ctx->raw_buf.size );
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
msg_acc_disk( fd_snapzp_t * ctx,
              ulong         seq,       /* unused */
              ulong         sig,       /* data pointer */
              ulong         chunk,     /* descriptor pointer */
              ulong         sz,        /* descriptor size */
              ulong         ctl,       /* holds orig, som, eom */
              ulong         tsorig,    /* unused */
              ulong         tspub ) {  /* data size */
  (void)seq; (void)tsorig;
  int som = fd_frag_meta_ctl_som( ctl );
  int eom = fd_frag_meta_ctl_eom( ctl );

  /* begin defrag operation */
  ulong frag_sz = tspub;
  if( FD_UNLIKELY( som ) ) {
    FD_CHECK_CRIT( chunk>=ctx->snapmk_zp_chunk0 && chunk<=ctx->snapmk_zp_wmark && sz==sizeof(fd_backup_disk_msg_t),
                   "input frag bounds check failed: fd_backup_disk_msg_t(som=1)" );
    fd_backup_disk_msg_t const * frag = fd_chunk_to_laddr_const( ctx->snapmk_zp_mem, chunk );
    frag_sz = msg_acc_disk_start( ctx, frag );
    if( FD_UNLIKELY( tspub!=frag_sz ) ) {
      FD_LOG_CRIT(( "invalid accdb disk frag stream: size mismatch (%lu != %lu)", tspub, frag_sz ));
    }
  } else {
    FD_CHECK_CRIT( !sz, "invalid accdb disk frag stream: non-SOM frag must not have a descriptor" );
  }
  FD_CHECK_CRIT( !!ctx->disk.active, "invalid accdb disk frag stream: non-SOM frag seen but no active defrag op" );

  /* locate data pointer */
  uchar const * frag = NULL;
  if( FD_LIKELY( ctx->disk.data_rem ) ) {
    frag = fd_wksp_laddr_fast( ctx->snaprd_mem, sig );
  }

  /* defrag copy */
  ulong take = fd_ulong_min( ctx->disk.data_rem, frag_sz );
  if( FD_LIKELY( take ) ) {
    FD_CHECK_CRIT( ctx->raw_buf.size + take <= RAW_BUF_SZ,
                   "internal bounds check failed" );
    FD_CHECK_CRIT( (ulong)frag           >= ctx->snaprd_data0 &&
                   (ulong)frag + frag_sz <= ctx->snaprd_data1,
                   "snaprd bounds check failed" );
    fd_memcpy( ctx->raw + ctx->raw_buf.size, frag, take );
    ctx->raw_buf.size  += take;
    ctx->disk.data_rem -= take;
    frag_sz            -= take;
  }
  FD_CHECK_CRIT( !frag_sz, "invalid accdb disk frag stream: frag spans multiple accounts" );
  FD_CHECK_CRIT( !( !ctx->disk.data_rem && !eom ), "invalid accdb disk frag stream: non-EOM frag seen but data already complete" );

  /* finish defrag operation */
  if( eom ) {
    FD_CHECK_CRIT( !ctx->disk.data_rem, "invalid accdb disk frag stream: EOM frag seen but defrag not complete" );
    if( ctx->disk.data_pad ) {
      FD_TEST( ctx->raw_buf.size + ctx->disk.data_pad <= RAW_BUF_SZ );
      fd_memset( ctx->raw + ctx->raw_buf.size, 0, ctx->disk.data_pad );
      ctx->raw_buf.size += ctx->disk.data_pad;
    }
    ctx->metrics.accounts_compressed++;
    memset( &ctx->disk, 0, sizeof(ctx->disk) );
  }
}

/* msg_acc_disk instructions snapzp to compress a batch of unfragmented
   accounts that were read from the accdb disk file.  (fast path)  */

static void
msg_acc_disk_batch( fd_snapzp_t *                      ctx,
                    fd_backup_disk_batch_msg_t const * batch,
                    ulong                              sig ) {
  FD_CHECK_CRIT( ctx->snap_fd>=0, "invalid snapshot file descriptor" );
  FD_CHECK_CRIT( !ctx->disk.active, "received account batch while already processing a disk account" );

  fd_backup_accidx_t const * idx      = &ctx->acc_cache->idx;
  fd_accdb_accmeta_t const * acc_pool = idx->acc_pool;

  /* MLP gather of account index entries */
  static fd_accdb_accmeta_t const dead = {0};
  fd_accdb_accmeta_t const * gather[ FD_BACKUP_DISK_PARA ];
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    uint ai = batch->acc_idx[ i ];
    gather[ i ] = fd_backup_accidx_valid( idx, ai ) ? &acc_pool[ ai ] : &dead;
  }
  ulong lamports[ FD_BACKUP_DISK_PARA ];
  uint  exec_sz [ FD_BACKUP_DISK_PARA ];
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    lamports[ i ] = FD_VOLATILE_CONST( gather[ i ]->lamports        );
    exec_sz [ i ] = FD_VOLATILE_CONST( gather[ i ]->executable_size );
  }

  /* Bounds check batch (TOCTOU susceptible, but this is an accepted
     risk, as snapmk->snapzp is a trusted link) */
  uchar const * base = fd_wksp_laddr_fast( ctx->snaprd_mem, sig );
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    FD_CHECK_CRIT( ((ulong)base + batch->frag_off[ i ] >= ctx->snaprd_data0) &
                   ((ulong)base + batch->frag_off[ i ] + sizeof(fd_accdb_disk_meta_t) <= (ulong)ctx->snaprd_data1),
                   "account data bounds check fail" );
  }

  /* Sequential scan of disk data in frag */
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    uint acc_idx = batch->acc_idx[ i ];
    if( acc_idx==UINT_MAX ) continue;
    FD_CHECK_CRIT( fd_backup_accidx_valid( idx, acc_idx ), "account index bounds check fail" );

    fd_accdb_disk_meta_t const * dm = (fd_accdb_disk_meta_t const *)( base + batch->frag_off[ i ] );
    FD_CHECK_CRIT( (ulong)(dm+1) <= (ulong)ctx->snaprd_data1, "account data bounds check fail" );

    ulong data_len = (ulong)FD_ACCDB_SIZE_DATA( dm->size );
    FD_CHECK_CRIT( (ulong)(dm+1)+data_len <= (ulong)ctx->snaprd_data1, "account data bounds check fail" );

    /* validate that disk data matches index */
    FD_CHECK_CRIT( FD_ACCDB_SIZE_DATA( exec_sz[ i ] )==data_len, "account query corruption detected" );
    FD_CHECK_CRIT( !memcmp( gather[ i ]->key.pubkey, dm->pubkey, sizeof(fd_pubkey_t) ), "account query corruption detected" );

    ulong rec_sz   = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_len, 8UL );
    ulong data_pad = fd_ulong_align_up( data_len, 8UL ) - data_len;
    FD_CHECK_CRIT( rec_sz<=RAW_BUF_SZ, "oversize snapshot account record" );
    if( FD_UNLIKELY( ctx->raw_buf.size + rec_sz > RAW_BUF_SZ ) ) {
      zip_flush( ctx );
    }

    snap_acc_hdr_t * hdr = (snap_acc_hdr_t *)( ctx->raw + ctx->raw_buf.size );
    memset( hdr, 0, sizeof(snap_acc_hdr_t) );
    memcpy( hdr->pubkey.uc, dm->pubkey, sizeof(fd_pubkey_t) );
    memcpy( hdr->owner.uc,  dm->owner,  sizeof(fd_pubkey_t) );
    hdr->lamports   = lamports[ i ];
    hdr->executable = !!FD_ACCDB_SIZE_EXEC( exec_sz[ i ] );
    hdr->data_len   = data_len;
    ctx->raw_buf.size += sizeof(snap_acc_hdr_t);

    if( FD_LIKELY( data_len ) ) {
      uchar const * data = base + batch->frag_off[ i ] + sizeof(fd_accdb_disk_meta_t);
      fd_memcpy( ctx->raw + ctx->raw_buf.size, data, data_len );
      ctx->raw_buf.size += data_len;
    }
    if( data_pad ) {
      fd_memset( ctx->raw + ctx->raw_buf.size, 0, data_pad );
      ctx->raw_buf.size += data_pad;
    }
    ctx->metrics.accounts_compressed++;
  }
}

/* msg_done is called on all snapzp tiles once all account data has been
   compressed.  This causes snapzp to enter sleep state. */

static void
msg_done( fd_snapzp_t * ctx ) {
  /* Leave file descriptors open, but release local reference */
  ctx->snap_fd = -1;
}

/* returnable_frag is called for every message received from snapmk. */

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

# define MSG_TRANSLATE( msg_type ) __extension__({ \
    FD_CHECK_CRIT( chunk >= ctx->snapmk_zp_chunk0 && chunk <= ctx->snapmk_zp_wmark && sz==sizeof(msg_type), "input frag bounds check failed: " #msg_type ); \
    (msg_type const *)fd_chunk_to_laddr_const( ctx->snapmk_zp_mem, chunk ); \
  })

  switch( orig ) {
  case FD_BACKUP_ORIG_START:
    msg_start( ctx, MSG_TRANSLATE( fd_backup_start_msg_t ) );
    break;
  case FD_BACKUP_ORIG_ACC_CACHE:
    msg_acc_cache( ctx, MSG_TRANSLATE( fd_backup_cache_msg_t ) );
    zip_work( ctx );
    break;
  case FD_BACKUP_ORIG_ACC_DELTA:
    msg_acc_delta( ctx, MSG_TRANSLATE( fd_backup_delta_msg_t ) );
    zip_work( ctx );
    break;
  case FD_BACKUP_ORIG_ACC_DISK:
    msg_acc_disk( ctx, seq, sig, chunk, sz, ctl, tsorig, tspub );
    zip_work( ctx );
    break;
  case FD_BACKUP_ORIG_ACC_DISK_BATCH:
    msg_acc_disk_batch( ctx, MSG_TRANSLATE( fd_backup_disk_batch_msg_t ), sig );
    zip_work( ctx );
    break;
  case FD_BACKUP_ORIG_FLUSH:
    zip_flush( ctx );
    break;
  case FD_BACKUP_ORIG_DONE:
    msg_done( ctx );
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

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapzp = {
  .name                     = "snapzp",
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
