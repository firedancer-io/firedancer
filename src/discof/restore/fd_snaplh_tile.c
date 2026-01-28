#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
#include "../../util/io_uring/fd_io_uring_setup.h"
#include "../../util/io_uring/fd_io_uring_register.h"
#include "../../util/io_uring/fd_io_uring.h"
#include "generated/fd_snaplh_tile_seccomp.h"

#include "utils/fd_ssctrl.h"

#include <errno.h>
#include <sys/stat.h> /* fstat */
#include <fcntl.h>    /* open  */
#include <unistd.h>   /* close */

#include "../../vinyl/io/fd_vinyl_io_ur.h"

#define NAME "snaplh"

#define IN_CNT_MAX     (2UL)
#define IN_KIND_SNAPLV (0UL)
#define IN_KIND_SNAPWH (1UL)

#define VINYL_LTHASH_BLOCK_ALIGN  FD_VINYL_BSTREAM_BLOCK_SZ
#define VINYL_LTHASH_BLOCK_MAX_SZ (16UL<<20)
FD_STATIC_ASSERT( VINYL_LTHASH_BLOCK_MAX_SZ>(sizeof(fd_snapshot_full_account_t)+FD_VINYL_BSTREAM_BLOCK_SZ+2*VINYL_LTHASH_BLOCK_ALIGN), "VINYL_LTHASH_BLOCK_MAX_SZ" );

#define VINYL_LTHASH_RD_REQ_MAX   (32UL)
#define VINYL_LTHASH_IORING_DEPTH (2*VINYL_LTHASH_RD_REQ_MAX)

#define VINYL_LTHASH_IO_SPAD_MAX  (2<<20UL)

#define VINYL_LTHASH_RD_REQ_FREE  (0UL)
#define VINYL_LTHASH_RD_REQ_PEND  (1UL)
#define VINYL_LTHASH_RD_REQ_SENT  (2UL)

struct in_link_private {
  fd_wksp_t *  wksp;
  ulong        chunk0;
  ulong        wmark;
  ulong        mtu;
  void const * base;
  ulong *      seq_sync;  /* fseq->seq[0] */
};
typedef struct in_link_private in_link_t;

struct out_link_private {
  fd_wksp_t *  wksp;
  ulong        chunk0;
  ulong        wmark;
  ulong        chunk;
  ulong        mtu;
};
typedef struct out_link_private out_link_t;

struct fd_snaplh_tile {
  uint state;
  int  full;

  ulong seed;
  ulong lthash_tile_cnt;
  ulong lthash_tile_idx;
  ulong lthash_tile_add_cnt;
  ulong lthash_tile_sub_cnt;
  ulong lthash_tile_add_idx;
  ulong lthash_tile_sub_idx;
  ulong pairs_seen;
  ulong lthash_req_seen;

  /* Database params */
  ulong const * io_seed;

  fd_lthash_adder_t   adder[1];
  fd_lthash_adder_t   adder_sub[1];
  uchar               data[FD_RUNTIME_ACC_SZ_MAX];

  fd_lthash_value_t   running_lthash;
  fd_lthash_value_t   running_lthash_sub;

  struct {
    int               dev_fd;
    ulong             dev_sz;
    ulong             dev_base;
    void *            pair_mem;
    void *            pair_tmp;

    struct {
      fd_vinyl_bstream_phdr_t phdr  [VINYL_LTHASH_RD_REQ_MAX];
      fd_vinyl_io_rd_t        rd_req[VINYL_LTHASH_RD_REQ_MAX];
    } pending;
    ulong             pending_rd_req_cnt;

    fd_vinyl_io_t *   io;
  } vinyl;

  struct {
    struct {
      ulong accounts_hashed;
    } full;

    struct {
      ulong accounts_hashed;
    } incremental;
  } metrics;

  ulong       wh_finish_fseq;
  ulong       wh_last_in_seq;

  in_link_t   in[IN_CNT_MAX];
  uchar       in_kind[IN_CNT_MAX];
  out_link_t  out;

  /* io_uring setup */

  fd_io_uring_t ioring[1];
};

typedef struct fd_snaplh_tile fd_snaplh_t;

static inline int
should_shutdown( fd_snaplh_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return alignof(fd_snaplh_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplh_t),      sizeof(fd_snaplh_t)                                );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_BLOCK_MAX_SZ                          );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_BLOCK_MAX_SZ                          );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_BLOCK_MAX_SZ                          );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ  );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_io_ur_align(),    fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( VINYL_LTHASH_IORING_DEPTH, VINYL_LTHASH_IORING_DEPTH ) );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplh_t) );
}

static void
metrics_write( fd_snaplh_t * ctx ) {
  FD_MGAUGE_SET( SNAPLH, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, STATE,                       (ulong)(ctx->state) );
}

static inline int
should_hash_account( fd_snaplh_t * ctx ) {
  return (ctx->pairs_seen % ctx->lthash_tile_add_cnt)==ctx->lthash_tile_add_idx;
}

static inline int
should_process_lthash_request( fd_snaplh_t * ctx ) {
  return (ctx->lthash_req_seen % ctx->lthash_tile_sub_cnt)==ctx->lthash_tile_sub_idx;
}

FD_FN_UNUSED static void
streamlined_hash( fd_snaplh_t *       restrict ctx,
                  fd_lthash_adder_t * restrict adder,
                  fd_lthash_value_t * restrict running_lthash,
                  uchar const *       restrict _pair ) {
  uchar const * pair = _pair;
  fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t const *)pair;
  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta = (fd_account_meta_t const *)pair;
  pair += sizeof(fd_account_meta_t);
  uchar const * data = pair;

  ulong data_len      = meta->dlen;
  const char * pubkey = phdr->key.c;
  ulong lamports      = meta->lamports;
  const uchar * owner = meta->owner;
  uchar executable = (uchar)( !meta->executable ? 0U : 1U) ;

  if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) ) FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
  if( FD_UNLIKELY( lamports==0UL ) ) return;

  fd_lthash_adder_push_solana_account( adder,
                                       running_lthash,
                                       pubkey,
                                       data,
                                       data_len,
                                       lamports,
                                       executable,
                                       owner );

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

FD_FN_UNUSED static inline void
bd_read( int    fd,
         ulong  off,
         void * buf,
         ulong  sz ) {
  ssize_t ssz = pread( fd, buf, sz, (off_t)off );
  if( FD_LIKELY( ssz==(ssize_t)sz ) ) return;
  if( ssz<(ssize_t)0 ) FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (%i-%s)", fd, off, sz, errno, fd_io_strerror( errno ) ));
  /**/                 FD_LOG_CRIT(( "pread(fd %i,off %lu,sz %lu) failed (unexpected sz %li)", fd, off, sz, (long)ssz ));
}

FD_FN_UNUSED static void
handle_vinyl_lthash_request_bd( fd_snaplh_t *             ctx,
                                ulong                     seq,
                                fd_vinyl_bstream_phdr_t * acc_hdr ) {

  /* The bd version is blocking, therefore ctx->pending is not used. */
  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );

  ulong val_esz = fd_vinyl_bstream_ctl_sz( acc_hdr->ctl );
  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );

  /* dev_seq shows where the seq is physically located in device. */
  ulong dev_seq  = ( seq + ctx->vinyl.dev_base ) % ctx->vinyl.dev_sz;
  ulong rd_off   = fd_ulong_align_dn( dev_seq, FD_VINYL_BSTREAM_BLOCK_SZ );
  ulong pair_off = (dev_seq - rd_off);
  ulong rd_sz    = fd_ulong_align_up( pair_off + pair_sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  FD_TEST( rd_sz < VINYL_LTHASH_BLOCK_MAX_SZ );

  uchar * pair = ((uchar*)ctx->vinyl.pair_mem) + pair_off;
  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)pair;

  for(;;) {
    ulong sz    = rd_sz;
    ulong rsz   = fd_ulong_min( rd_sz, ctx->vinyl.dev_sz - rd_off );
    uchar * dst = ctx->vinyl.pair_mem;
    uchar * tmp = ctx->vinyl.pair_tmp;

    bd_read( ctx->vinyl.dev_fd, rd_off, dst, rsz );
    sz -= rsz;
    if( FD_UNLIKELY( sz ) ) {
      /* When the dev wraps around, the dev_base needs to be skipped.
         This means: increase the size multiple of the alignment,
         read into a temporary buffer, and memcpy into the dst at the
         correct offset. */
      bd_read( ctx->vinyl.dev_fd, 0, tmp, sz + FD_VINYL_BSTREAM_BLOCK_SZ );
      fd_memcpy( dst + rsz, tmp + ctx->vinyl.dev_base, sz );
    }

    if( FD_LIKELY( !memcmp( phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t)) ) ) {

      /* test bstream pair integrity hashes */
      int test = !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz );
      if( FD_LIKELY( test ) ) break;
    }
    FD_LOG_WARNING(( "phdr mismatch! - this should not happen under bstream_seq" ));
    FD_SPIN_PAUSE();
  }

  streamlined_hash( ctx, ctx->adder_sub, &ctx->running_lthash_sub, pair );
}

FD_FN_UNUSED static inline ulong
rd_req_ctx_get_idx( ulong rd_req_ctx ) {
  return ( rd_req_ctx >>  0 ) & ((1UL<<32)-1UL);
}

FD_FN_UNUSED static inline ulong
rd_req_ctx_get_status( ulong rd_req_ctx ) {
  return ( rd_req_ctx >> 32 ) & ((1UL<<32)-1UL);
}

FD_FN_UNUSED static inline void
rd_req_ctx_into_parts( ulong   rd_req_ctx,
                       ulong * idx,
                       ulong * status ) {
  *idx    = rd_req_ctx_get_idx( rd_req_ctx );
  *status = rd_req_ctx_get_status( rd_req_ctx );
}

FD_FN_UNUSED static inline ulong
rd_req_ctx_from_parts( ulong idx,
                       ulong status ) {
  return ( idx & ((1UL<<32)-1UL) ) | ( status << 32 );
}

FD_FN_UNUSED static inline ulong
rd_req_ctx_update_status( ulong rd_req_ctx,
                          ulong status ) {
  return rd_req_ctx_from_parts( rd_req_ctx_get_idx( rd_req_ctx ), status );
}

FD_FN_UNUSED static void
handle_vinyl_lthash_compute_from_rd_req( fd_snaplh_t *      ctx,
                                         fd_vinyl_io_rd_t * rd_req ) {
  ulong idx = rd_req_ctx_get_idx( rd_req->ctx );

  fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)rd_req->dst;
  fd_vinyl_bstream_phdr_t * acc_hdr = &ctx->vinyl.pending.phdr[ idx ];

  /* test the retrieved header (it must mach the request) */
  FD_TEST( !memcmp( phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t)) );

  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );
  ulong   seq     = rd_req->seq;
  uchar * pair    = (uchar*)rd_req->dst;
  ulong   pair_sz = rd_req->sz;

  /* test the bstream pair integrity hashes */
  FD_TEST( !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz ) );

  streamlined_hash( ctx, ctx->adder_sub, &ctx->running_lthash_sub, pair );
}

/* Process next read completion */

static inline ulong
consume_available_cqe( fd_snaplh_t * ctx ) {
  if( FD_LIKELY( !ctx->vinyl.pending_rd_req_cnt ) ) return 0UL;
  if( ctx->vinyl.io->type!=FD_VINYL_IO_TYPE_UR ) return 0UL;
  if( !fd_io_uring_cq_ready( ctx->ioring->cq ) ) return 0UL;

  /* At this point, there is at least one unconsumed CQE */

  fd_vinyl_io_rd_t * rd_req = NULL;
  if( FD_LIKELY( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, 0/*non blocking*/ )==FD_VINYL_SUCCESS ) ) {
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    ctx->vinyl.pending_rd_req_cnt--;
    return 1UL;
  }
  return 0UL;
}

FD_FN_UNUSED static void
handle_vinyl_lthash_request_ur( fd_snaplh_t *             ctx,
                                ulong                     seq,
                                fd_vinyl_bstream_phdr_t * acc_hdr ) {
  /* Find a free slot */
  ulong free_i = ULONG_MAX;
  if( FD_LIKELY( ctx->vinyl.pending_rd_req_cnt<VINYL_LTHASH_RD_REQ_MAX ) ) {
    for( ulong i=0UL; i<VINYL_LTHASH_RD_REQ_MAX; i++ ) {
      fd_vinyl_io_rd_t * rd_req = &ctx->vinyl.pending.rd_req[ i ];
      if( FD_UNLIKELY( rd_req_ctx_get_status( rd_req->ctx )==VINYL_LTHASH_RD_REQ_FREE ) ) {
        free_i = i;
        break;
      }
    }
  } else {
    fd_vinyl_io_rd_t * rd_req = NULL;
    fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING );
    FD_TEST( rd_req!=NULL );
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    free_i      = rd_req_ctx_get_idx( rd_req->ctx );
    ctx->vinyl.pending_rd_req_cnt--;
  }
  FD_CRIT( free_i<VINYL_LTHASH_RD_REQ_MAX, "read request free index exceeds max value" );

  /* Populate the empty slot and submit */
  fd_vinyl_bstream_phdr_t * in_phdr = &ctx->vinyl.pending.phdr[ free_i ];
  memcpy( in_phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t) );
  ulong val_esz = fd_vinyl_bstream_ctl_sz( acc_hdr->ctl );
  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );

  fd_vinyl_io_rd_t * rd_req  = &ctx->vinyl.pending.rd_req[ free_i ];
  rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_PEND );
  rd_req->seq = seq;
  rd_req->sz  = pair_sz;
  fd_vinyl_io_read( ctx->vinyl.io, rd_req );
  rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_SENT );
  ctx->vinyl.pending_rd_req_cnt++;
}

FD_FN_UNUSED static void
handle_vinyl_lthash_request_ur_consume_all( fd_snaplh_t * ctx ) {
  while( ctx->vinyl.pending_rd_req_cnt ) {
    fd_vinyl_io_rd_t * rd_req = NULL;
    fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING );
    FD_TEST( rd_req!=NULL );
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    ctx->vinyl.pending_rd_req_cnt--;
  }
  FD_CRIT( !ctx->vinyl.pending_rd_req_cnt, "pending read requests count not zero" );
  for( ulong i=0UL; i<VINYL_LTHASH_RD_REQ_MAX; i++ ) {
    fd_vinyl_io_rd_t * rd_req = &ctx->vinyl.pending.rd_req[ i ];
    FD_CRIT( rd_req_ctx_get_status( rd_req->ctx )==VINYL_LTHASH_RD_REQ_FREE, "pending request status is not free" );
  }
}

FD_FN_UNUSED static uint
handle_lthash_completion( fd_snaplh_t * ctx,
                          fd_stem_context_t * stem ) {
  fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
  fd_lthash_adder_flush( ctx->adder_sub, &ctx->running_lthash_sub );
  if( fd_seq_inc( ctx->wh_last_in_seq, 1UL )==ctx->wh_finish_fseq ) {
    fd_lthash_sub( &ctx->running_lthash, &ctx->running_lthash_sub );
    uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
    fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
    fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
    return FD_SNAPSHOT_STATE_IDLE;
  }
  return ctx->state;
}

static void
before_credit( fd_snaplh_t *       ctx,
               fd_stem_context_t * stem FD_PARAM_UNUSED,
               int *               charge_busy ) {
  *charge_busy = !!consume_available_cqe( ctx );
}

static void
handle_wh_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         chunk,      /* compressed input pointer */
                     ulong         sz_comp,    /* compressed input size */
                     fd_stem_context_t * stem ) {
  FD_CRIT( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH, "incorrect in kind" );

  uchar const * rem    = fd_chunk_to_laddr_const( ctx->in[ in_idx ].base, chunk );
  ulong         rem_sz = sz_comp<<FD_VINYL_BSTREAM_BLOCK_LG_SZ;
  FD_CRIT( fd_ulong_is_aligned( (ulong)rem, FD_VINYL_BSTREAM_BLOCK_SZ ), "misaligned write request" );
  FD_CRIT( fd_ulong_is_aligned( rem_sz, FD_VINYL_BSTREAM_BLOCK_SZ ),     "misaligned write request" );

  while( rem_sz ) {
    FD_CRIT( rem_sz>=FD_VINYL_BSTREAM_BLOCK_SZ, "corrupted bstream block" );

    fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t *)rem;
    ulong ctl      = phdr->ctl;
    int   ctl_type = fd_vinyl_bstream_ctl_type( ctl );
    switch( ctl_type ) {

      case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {
        ulong val_esz = fd_vinyl_bstream_ctl_sz( ctl );
        ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );
        if( FD_LIKELY( should_hash_account( ctx ) ) ) {
          uchar * pair = ctx->vinyl.pair_mem;
          fd_memcpy( pair, rem, pair_sz );
          streamlined_hash( ctx, ctx->adder, &ctx->running_lthash, pair );
        }
        rem    += pair_sz;
        rem_sz -= pair_sz;
        ctx->pairs_seen++;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {
        rem    += FD_VINYL_BSTREAM_BLOCK_SZ;
        rem_sz -= FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      default:
        FD_LOG_CRIT(( "unexpected vinyl bstream block ctl=%016lx", ctl ));
    }
  }

  if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
    ctx->state = handle_lthash_completion( ctx, stem );
  }
}

static void
handle_lv_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         chunk,      /* compressed input pointer */
                     ulong         sz_comp ) { /* compressed input size */
  (void)sz_comp;
  if( FD_LIKELY( should_process_lthash_request( ctx ) ) ) {
    uchar const * indata = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
    ulong seq;
    fd_vinyl_bstream_phdr_t acc_hdr[1];
    memcpy( &seq,    indata, sizeof(ulong) );
    memcpy( acc_hdr, indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
    if( FD_LIKELY( ctx->vinyl.io->type==FD_VINYL_IO_TYPE_UR ) ) {
      handle_vinyl_lthash_request_ur( ctx, seq, acc_hdr );
    } else {
      handle_vinyl_lthash_request_bd( ctx, seq, acc_hdr );
    }
  }
  ctx->lthash_req_seen++;
}

static inline ulong
tsorig_tspub_to_fseq( ulong tsorig,
                      ulong tspub ) {
  return (tspub<<32 ) | tsorig;
}

static void
handle_control_frag( fd_snaplh_t * ctx,
                     ulong         sig,
                     ulong         tsorig,
                     ulong         tspub,
                    fd_stem_context_t * stem  ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->full  = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      fd_lthash_zero( &ctx->running_lthash );
      fd_lthash_zero( &ctx->running_lthash_sub );
      fd_lthash_adder_new( ctx->adder );
      fd_lthash_adder_new( ctx->adder_sub );
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      fd_lthash_zero( &ctx->running_lthash_sub );
      fd_lthash_adder_new( ctx->adder );
      fd_lthash_adder_new( ctx->adder_sub );
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE:{
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING  ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->wh_finish_fseq = tsorig_tspub_to_fseq( tsorig, tspub );
      ctx->state = FD_SNAPSHOT_STATE_FINISHING;

      if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
        if( FD_LIKELY( ctx->vinyl.io->type==FD_VINYL_IO_TYPE_UR ) ) {
          handle_vinyl_lthash_request_ur_consume_all( ctx );
        }
        ctx->state = handle_lthash_completion( ctx, stem );
      }
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }
}

static inline int
returnable_frag( fd_snaplh_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH ) )          handle_wh_data_frag( ctx, in_idx, chunk, sz/*sz_comp*/, stem );
  else if( FD_UNLIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_META_BATCH ) ) handle_lv_data_frag( ctx, in_idx, chunk, sz );
  else                                                               handle_control_frag( ctx, sig, tsorig, tspub, stem );

  /* Because fd_stem may not return flow control credits fast enough,
     always update fseq (consumer progress) here. */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH ) ) {
    ctx->wh_last_in_seq = seq;
    fd_fseq_update( ctx->in[ in_idx ].seq_sync, fd_seq_inc( seq, 1UL ) );
  }

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t), sizeof(fd_snaplh_t) );

  out_fds[ out_cnt++ ] = ctx->vinyl.dev_fd;

  if( FD_LIKELY( ctx->ioring->ioring_fd>=0 ) ) {
    out_fds[ out_cnt++ ] = ctx->ioring->ioring_fd;
  }

  return out_cnt;
}

static void
during_housekeeping( fd_snaplh_t * ctx ) {

  /* Service io_uring instance */

  if( ctx->vinyl.io->type==FD_VINYL_IO_TYPE_UR ) {
    uint sq_drops = fd_io_uring_sq_dropped( ctx->ioring->sq );
    if( FD_UNLIKELY( sq_drops ) ) {
      FD_LOG_CRIT(( "kernel io_uring dropped I/O requests, cannot continue (sq_dropped=%u)", sq_drops ));
    }

    uint cq_drops = fd_io_uring_cq_overflow( ctx->ioring->cq );
    if( FD_UNLIKELY( cq_drops ) ) {
      FD_LOG_CRIT(( "kernel io_uring dropped I/O completions, cannot continue (cq_overflow=%u)", cq_drops ));
    }
  }

}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t), sizeof(fd_snaplh_t) );

  populate_sock_filter_policy_fd_snaplh_tile( out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->vinyl.dev_fd,
      (uint)ctx->ioring->ioring_fd /* possibly -1 */ );
  return sock_filter_policy_fd_snaplh_tile_instr_cnt;
}

static fd_vinyl_io_t *
snaplh_io_uring_init( fd_snaplh_t * ctx,
                      void *        uring_shmem,
                      void *        vinyl_io_ur_mem,
                      int           dev_fd ) {
  ulong const uring_depth = VINYL_LTHASH_IORING_DEPTH;
  struct io_uring_params params[1];
  fd_io_uring_params_init( params, uring_depth );

  if( FD_UNLIKELY( !fd_io_uring_init_shmem( ctx->ioring, params, uring_shmem, uring_depth, uring_depth ) ) ) {
    FD_LOG_ERR(( "fd_io_uring_init_shmem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_io_uring_t * ioring = ctx->ioring;

  if( FD_UNLIKELY( fd_io_uring_register_files( ioring->ioring_fd, &dev_fd, 1 )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_files failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct io_uring_restriction res[3] = {
    { .opcode    = IORING_RESTRICTION_SQE_OP,
      .sqe_op    = IORING_OP_READ },
    { .opcode    = IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
      .sqe_flags = IOSQE_FIXED_FILE },
    { .opcode    = IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
      .sqe_flags = IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS }
  };
  if( FD_UNLIKELY( fd_io_uring_register_restrictions( ioring->ioring_fd, res, 3U )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_restrictions failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fd_io_uring_enable_rings( ioring->ioring_fd )<0 ) ) {
    FD_LOG_ERR(( "io_uring_enable_rings failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  ulong align = fd_vinyl_io_ur_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = fd_vinyl_io_ur_footprint( VINYL_LTHASH_IO_SPAD_MAX );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  /* Before invoking fd_vinyl_io_ur_init, the sync block must be
     already available.  Although in principle one could keep
     calling fd_vinyl_io_ur_init until it returns !=NULL, doing this
     would log uncessary (and misleading) warnings. */
  FD_LOG_INFO(( "waiting for account database creation" ));
  for(;;) {
    fd_vinyl_bstream_block_t block[1];
    ulong dev_sync = 0UL; /* Use the beginning of the file for the sync block */
    bd_read( dev_fd, dev_sync, block, FD_VINYL_BSTREAM_BLOCK_SZ );
    int type = fd_vinyl_bstream_ctl_type( block->sync.ctl );
    if( FD_UNLIKELY( type != FD_VINYL_BSTREAM_CTL_TYPE_SYNC ) ) continue;
    ulong io_seed = block->sync.hash_trail;
    if( FD_LIKELY( !fd_vinyl_bstream_block_test( io_seed, block ) ) ) break;
    fd_log_sleep( 1e6 ); /* 1ms */
  }
  FD_LOG_INFO(( "found valid account database sync block, attaching ..." ));

  fd_vinyl_io_t * io = fd_vinyl_io_ur_init( vinyl_io_ur_mem, VINYL_LTHASH_IO_SPAD_MAX, dev_fd, ioring );
  if( FD_UNLIKELY( !io ) ) FD_LOG_ERR(( "vinyl_io_ur_init failed" ));
  return io;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),      sizeof(fd_snaplh_t)                                );
  void * pair_mem    = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_BLOCK_MAX_SZ                          ); (void)pair_mem;
  void * pair_tmp    = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_BLOCK_MAX_SZ                          ); (void)pair_tmp;
  void * rd_req_mem  = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN,  VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ  ); (void)rd_req_mem;
  void * uring_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_ur_align(),    fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  void * uring_shmem = FD_SCRATCH_ALLOC_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( VINYL_LTHASH_IORING_DEPTH, VINYL_LTHASH_IORING_DEPTH ) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  /* Set up io_bd dependencies */

  char const * bstream_path = tile->snaplh.vinyl_path;
  /* Note: it would be possible to use O_DIRECT, but it would require
     FD_VINYL_BSTREAM_BLOCK_SZ to be 4096UL, which substantially
     increases the read overhead, making it slower (keep in mind that
     a rather large subset of mainnet accounts typically fits inside
     one FD_VINYL_BSTREAM_BLOCK_SZ. */
  int dev_fd = open( bstream_path, O_RDONLY|O_CLOEXEC, 0444 );
  if( FD_UNLIKELY( dev_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s,O_RDONLY|O_CLOEXEC, 0444) failed (%i-%s)",
                 bstream_path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( dev_fd, &st ) ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", bstream_path, errno, strerror( errno ) ));

  ctx->vinyl.dev_fd  = dev_fd;
  ulong bstream_sz   = (ulong)st.st_size;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( bstream_sz, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_ERR(( "vinyl file %s has misaligned size (%lu bytes)", bstream_path, bstream_sz ));
  }
  ctx->vinyl.dev_sz   = bstream_sz;
  ctx->vinyl.dev_base = FD_VINYL_BSTREAM_BLOCK_SZ;

  ctx->vinyl.io = NULL;
  ctx->ioring->ioring_fd = -1;

  if( FD_LIKELY( tile->snaplh.io_uring_enabled ) ) {
    ctx->vinyl.io = snaplh_io_uring_init( ctx, uring_shmem, uring_mem, dev_fd );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),     sizeof(fd_snaplh_t)                               );
  void *   pair_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                         );
  void *   pair_tmp = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                         );
  void * rd_req_mem = NULL;
  rd_req_mem        = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ );

  FD_TEST( fd_topo_tile_name_cnt( topo, "snaplh" )<=FD_SNAPSHOT_MAX_SNAPLH_TILES );

  ctx->vinyl.pair_mem = pair_mem;
  ctx->vinyl.pair_tmp = pair_tmp;

  if( FD_UNLIKELY( tile->in_cnt!=IN_CNT_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected %lu", tile->in_cnt, IN_CNT_MAX ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL       ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1",  tile->out_cnt            ));

  ctx->io_seed = NULL;

  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    if( FD_LIKELY( 0==strcmp( in_link->name, "snaplv_lh" ) ) ) {
      ctx->in[ i ].wksp     = in_wksp->wksp;
      ctx->in[ i ].chunk0   = fd_dcache_compact_chunk0( ctx->in[ i ].wksp, in_link->dcache );
      ctx->in[ i ].wmark    = fd_dcache_compact_wmark( ctx->in[ i ].wksp, in_link->dcache, in_link->mtu );
      ctx->in[ i ].mtu      = in_link->mtu;
      ctx->in[ i ].base     = NULL;
      ctx->in[ i ].seq_sync = NULL;
      ctx->in_kind[ i ]     = IN_KIND_SNAPLV;
    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snapwh_wr" ) ) ) {
      ctx->in[ i ].wksp     = in_wksp->wksp;
      ctx->in[ i ].chunk0   = 0;
      ctx->in[ i ].wmark    = 0;
      ctx->in[ i ].mtu      = 0;
      ctx->in[ i ].base     = fd_dcache_join( fd_topo_obj_laddr( topo, tile->snaplh.dcache_obj_id ) );
      ctx->in[ i ].seq_sync = tile->in_link_fseq[ i ];
      ctx->wh_last_in_seq   = fd_fseq_query( tile->in_link_fseq[ i ] );
      ctx->in_kind[ i ]     = IN_KIND_SNAPWH;
      ctx->io_seed          = (ulong const *)fd_dcache_app_laddr_const( ctx->in[ i ].base );
      FD_TEST( ctx->in[ i ].base );
    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  FD_TEST( ctx->io_seed );

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( out_link->dcache ), out_link->dcache );
  ctx->out.wmark   = fd_dcache_compact_wmark ( ctx->out.wksp, out_link->dcache, out_link->mtu );
  ctx->out.chunk   = ctx->out.chunk0;
  ctx->out.mtu     = out_link->mtu;
  FD_TEST( 0==strcmp( out_link->name, "snaplh_lv" ) );

  fd_lthash_adder_new( ctx->adder );
  fd_lthash_adder_new( ctx->adder_sub );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  memset( ctx->vinyl.pending.phdr,   0, sizeof(fd_vinyl_bstream_phdr_t) * VINYL_LTHASH_RD_REQ_MAX );
  memset( ctx->vinyl.pending.rd_req, 0, sizeof(fd_vinyl_io_rd_t)        * VINYL_LTHASH_RD_REQ_MAX );
  for( ulong i=0UL; i<VINYL_LTHASH_RD_REQ_MAX; i++ ) {
    fd_vinyl_io_rd_t * rd_req = &ctx->vinyl.pending.rd_req[ i ];
    rd_req->ctx = rd_req_ctx_from_parts( i, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->dst = NULL;
    if( rd_req_mem!=NULL ) {
      rd_req->dst = ((uchar*)rd_req_mem) + i*VINYL_LTHASH_BLOCK_MAX_SZ;
    }
  }
  ctx->vinyl.pending_rd_req_cnt = 0UL;

  ctx->state                   = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                    = 1;
  ctx->lthash_tile_cnt         = fd_topo_tile_name_cnt( topo, "snaplh" );
  ctx->lthash_tile_idx         = tile->kind_id;
  /* This may seem redundant, but it provides flexibility around which
     tiles and do addition and subtraction of lthash. */
  ctx->lthash_tile_add_cnt     = ctx->lthash_tile_cnt;
  ctx->lthash_tile_sub_cnt     = ctx->lthash_tile_cnt;
  ctx->lthash_tile_add_idx     = ctx->lthash_tile_idx;
  ctx->lthash_tile_sub_idx     = ctx->lthash_tile_idx;
  if( ctx->lthash_tile_add_idx != ULONG_MAX ) FD_TEST( ctx->lthash_tile_add_idx < ctx->lthash_tile_add_cnt );
  if( ctx->lthash_tile_sub_idx != ULONG_MAX ) FD_TEST( ctx->lthash_tile_sub_idx < ctx->lthash_tile_sub_cnt );
  ctx->pairs_seen              = 0UL;
  ctx->lthash_req_seen         = 0UL;
  fd_lthash_zero( &ctx->running_lthash );
  fd_lthash_zero( &ctx->running_lthash_sub );
}

#define STEM_BURST 1UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplh_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplh_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplh = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
