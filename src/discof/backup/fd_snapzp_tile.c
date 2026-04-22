//#include "fd_snapmk.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

struct fd_snapzp {
  fd_funk_t funk[1];

  fd_pubkey_t account;
  uchar       data[ FD_RUNTIME_ACC_SZ_MAX ];

  ZSTD_CCtx *    zst;
  uchar *        raw;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;

  ulong idle_cnt;

  struct {
    ulong accounts_compressed;
    ulong bytes_compressed;
  } metrics;
};
typedef struct fd_snapzp fd_snapzp_t;

#define RAW_BUF_SZ  (32UL<<20) /* FIXME make this configurable */
#define COMP_BUF_SZ ZSTD_COMPRESSBOUND( RAW_BUF_SZ )

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  l = FD_LAYOUT_APPEND( l, 4096UL,               RAW_BUF_SZ          );
  l = FD_LAYOUT_APPEND( l, 4096UL,               COMP_BUF_SZ         );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapzp_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  uchar *       raw_buf  = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,               RAW_BUF_SZ          );
  uchar *       comp_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,               COMP_BUF_SZ         );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  memset( ctx, 0, sizeof(fd_snapzp_t) );

  ulong funk_obj_id;  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ) )!=ULONG_MAX );
  ulong locks_obj_id; FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ) ) );

  ctx->zst = ZSTD_createCCtx(); /* FIXME no libc alloc */
  FD_TEST( ctx->zst );
  ulong zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, 1 );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel=1) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->raw = raw_buf;
  ctx->raw_buf  = (ZSTD_inBuffer){ .src = raw_buf,  .size = RAW_BUF_SZ };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = comp_buf, .size = COMP_BUF_SZ };
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

union __attribute__((packed)) snap_acc_hdr {
  struct __attribute__((packed)) {
    /* 0x00 */ ulong       slot;
    /* 0x08 */ ulong       data_len;
    /* 0x10 */ fd_pubkey_t pubkey;
    /* 0x30 */ ulong       lamports;
    /* 0x38 */ ulong       rent_epoch;
    /* 0x40 */ fd_pubkey_t owner;
    /* 0x60 */ uchar       executable;
    /* 0x61 */ uchar       padding[7];
    /* 0x68 */ fd_hash_t   hash;
    /* 0x88 */
  };
  uchar raw[ 0x88 ];
};
typedef union snap_acc_hdr snap_acc_hdr_t;

static void
before_credit( fd_snapzp_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem; (void)charge_busy;
  if( FD_UNLIKELY( ctx->idle_cnt++ > 65536UL ) ) {
    fd_log_sleep( (long)1e6 );
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
  (void)in_idx; (void)seq; (void)chunk; (void)sz; (void)ctl; (void)stem;
  ctx->idle_cnt = 0UL;
  ulong rec_idx   = tsorig;
  ulong data_sz   = tspub;
  ulong val_gaddr = sig;

  fd_funk_rec_t const *     rec       = &ctx->funk->rec_pool->ele[ rec_idx ];
  fd_account_meta_t const * val       = fd_wksp_laddr_fast( ctx->funk->wksp, val_gaddr );
  ulong                     raw_chunk = sizeof(snap_acc_hdr_t) + data_sz;
  ctx->metrics.accounts_compressed++;
  ctx->metrics.bytes_compressed += raw_chunk;

  if( FD_UNLIKELY( ctx->raw_buf.size+raw_chunk > RAW_BUF_SZ ) ) {
    /* Cannot extend input buffer, finish frame */
    ctx->comp_buf.pos = 0UL;
    ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, ZSTD_e_end );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) failed: %s", ZSTD_getErrorName( ret ) ));
    }
    if( FD_UNLIKELY( ret!=0UL ) ) {
      FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_end) did not finish frame" ));
    }
    FD_TEST( ctx->raw_buf.pos == ctx->raw_buf.size );
    ctx->raw_buf.pos  = 0UL;
    ctx->raw_buf.size = 0UL;
  }

  /* Append account to buffer */
  snap_acc_hdr_t hdr = {
    .slot       = val->slot,
    .data_len   = data_sz,
    .pubkey     = FD_LOAD( fd_pubkey_t, rec->pair.key ),
    .lamports   = val->lamports,
    .rent_epoch = ULONG_MAX, /* can we write 0UL here? (compresses better) */
    .owner      = FD_LOAD( fd_pubkey_t, val->owner ),
    .executable = !!val->executable,
    .hash       = {{0}} /* FIXME is this required */
  };
  uchar * raw = ctx->raw;
  fd_memcpy( raw + ctx->raw_buf.size, hdr.raw, sizeof(hdr) );
  ctx->raw_buf.size += sizeof(snap_acc_hdr_t);
  fd_memcpy( raw + ctx->raw_buf.size, fd_account_data( val ), data_sz );
  ctx->raw_buf.size += data_sz;

  /* Do some work */
  if( FD_UNLIKELY( ctx->raw_buf.size - ctx->raw_buf.pos >= (128UL<<10) ) ) {
    ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, ZSTD_e_continue );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_ERR(( "ZSTD_compressStream2(ZSTD_e_continue) failed: %s", ZSTD_getErrorName( ret ) ));
    }
  }

  return 0;
}

static void
metrics_write( fd_snapzp_t * ctx ) {
  FD_MCNT_SET( SNAPZP, ACCOUNTS_COMPRESSED, ctx->metrics.accounts_compressed );
  FD_MCNT_SET( SNAPZP, BYTES_COMPRESSED, ctx->metrics.bytes_compressed );
}

#define STEM_BURST 1UL
#define STEM_LAZY  9400UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapzp_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapzp_t)
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem1.c"

fd_topo_run_tile_t fd_tile_snapzp = {
  .name                     = "snapzp",
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
