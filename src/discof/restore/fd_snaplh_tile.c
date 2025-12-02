#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "generated/fd_snaplh_tile_seccomp.h"

#include "utils/fd_ssctrl.h"

#include <errno.h>
#include <sys/stat.h> /* fstat */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */

#if FD_HAS_LIBURING
#define IO_URING_ENABLED (1)
#else
#define IO_URING_ENABLED (0)
#endif
// #define IO_URING_ENABLED (1)

#if IO_URING_ENABLED
#include "../../vinyl/io/fd_vinyl_io_ur.h"
#include <liburing.h>
#endif

#define NAME "snaplh"

#define IN_KIND_SNAPLV (0UL)
#define IN_KIND_SNAPWH (1UL)

#define VINYL_LTHASH_BLOCK_ALIGN  (512UL) /* O_DIRECT would require 4096UL */
#define VINYL_LTHASH_BLOCK_MAX_SZ (16UL<<20)
FD_STATIC_ASSERT( VINYL_LTHASH_BLOCK_MAX_SZ>(sizeof(fd_snapshot_full_account_t)+FD_VINYL_BSTREAM_BLOCK_SZ+2*VINYL_LTHASH_BLOCK_ALIGN), "VINYL_LTHASH_BLOCK_MAX_SZ" );

#define VINYL_LTHASH_RD_REQ_MAX   (64UL)

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
  fd_wksp_t * wksp;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct out_link_private out_link_t;

struct fd_snaplh_tile {
  int state;
  int full;

  ulong seed;
  int   hash_account;
  ulong num_hash_tiles;
  ulong hash_tile_idx;
  ulong pairs_seen;
  ulong lthash_req_seen;

  /* Database params */
  ulong const * io_seed;

  ulong  finish_fseq;

  fd_lthash_adder_t adder[1];
  fd_lthash_adder_t adder_sub[1];
  uchar             data[ FD_RUNTIME_ACC_SZ_MAX ];
  ulong             acc_data_sz;

  fd_lthash_value_t        running_lthash;
  fd_lthash_value_t        running_lthash_sub;

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
    ulong             rd_req_cnt;

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

  ulong       last_in_seq;
  in_link_t   in[2];
  uchar       in_kind[2];
  out_link_t  out;
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplh_t),     sizeof(fd_snaplh_t)                                );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                          );
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                          );
  #if IO_URING_ENABLED
  l = FD_LAYOUT_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ  );
  l = FD_LAYOUT_APPEND( l, alignof(struct io_uring), sizeof(struct io_uring)                            );
  l = FD_LAYOUT_APPEND( l, fd_vinyl_io_ur_align(),   fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  #endif
  return FD_LAYOUT_FINI( l, alignof(fd_snaplh_t) );
}

static void
metrics_write( fd_snaplh_t * ctx ) {
  FD_MGAUGE_SET( SNAPLH, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLH, STATE,                       (ulong)(ctx->state) );
}

static int
should_hash_account( fd_snaplh_t * ctx ) {
  return (ctx->pairs_seen % ctx->num_hash_tiles)==ctx->hash_tile_idx;
}

static int
should_process_lthash_request( fd_snaplh_t * ctx ) {
  return (ctx->lthash_req_seen % ctx->num_hash_tiles)==ctx->hash_tile_idx;
}

FD_FN_UNUSED static void
streamlined_hash( fd_snaplh_t *       ctx,
                  fd_lthash_adder_t * adder,
                  fd_lthash_value_t * running_lthash,
                  uchar const *       _pair ) {
  uchar const * pair = _pair;
  fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t const *)pair;
  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta = (fd_account_meta_t const *)pair;
  pair += sizeof(fd_account_meta_t);
  uchar const * data = pair;

  ulong data_len   = meta->dlen;
  uchar pubkey[32];  memcpy( pubkey, phdr->key.c, 32UL );
  ulong lamports   = meta->lamports;
  uchar owner[32];   memcpy( owner, meta->owner, 32UL );
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

  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );

  ulong val_esz = fd_vinyl_bstream_ctl_sz( acc_hdr->ctl );
  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );

  /* dev_seq shows where the seq is physically located in device. */
  ulong dev_seq  = ( seq + ctx->vinyl.dev_base ) % ctx->vinyl.dev_sz;
  ulong rd_off   = fd_ulong_align_dn( dev_seq, VINYL_LTHASH_BLOCK_ALIGN );
  ulong pair_off = (dev_seq - rd_off);
  ulong rd_sz    = fd_ulong_align_up( pair_off + pair_sz, VINYL_LTHASH_BLOCK_ALIGN );
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
      bd_read( ctx->vinyl.dev_fd, 0, tmp, sz + VINYL_LTHASH_BLOCK_ALIGN );
      fd_memcpy( dst + rsz, tmp + ctx->vinyl.dev_base, sz );
    }

    if( FD_LIKELY( !memcmp( phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t)) ) ) {

      /* test bstream pair integrity hashes */
      // fd_vinyl_bstream_block_t * pair_hdr = (fd_vinyl_bstream_block_t *)pair;
      // fd_vinyl_bstream_block_t * pair_ftr = (fd_vinyl_bstream_block_t *)(pair+(pair_sz-FD_VINYL_BSTREAM_BLOCK_SZ));
      // int test = !fd_vinyl_bstream_pair_test_fast( io_seed, seq, pair_hdr, pair_ftr );
      int test = !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz );

      if( FD_LIKELY( test ) ) {
        break;
      }
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

  FD_TEST( !memcmp( phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t)) );

  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );
  ulong   seq     = rd_req->seq;
  uchar * pair    = (uchar*)rd_req->dst;
  ulong   pair_sz = rd_req->sz;

  /* test bstream pair integrity hashes */
  // fd_vinyl_bstream_block_t * pair_hdr = (fd_vinyl_bstream_block_t *)pair;
  // fd_vinyl_bstream_block_t * pair_ftr = (fd_vinyl_bstream_block_t *)(pair+(pair_sz-FD_VINYL_BSTREAM_BLOCK_SZ));
  // int test = !fd_vinyl_bstream_pair_test_fast( io_seed, seq, pair_hdr, pair_ftr );
  int test = !fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz );
  FD_TEST( test );

  streamlined_hash( ctx, ctx->adder_sub, &ctx->running_lthash_sub, pair );
}

#if 0
FD_FN_UNUSED static void
handle_vinyl_lthash_request_ur( fd_snaplh_t *             ctx,
                                ulong                     seq,
                                fd_vinyl_bstream_phdr_t * acc_hdr ) {

  ulong free_i = 0UL;
  ulong *                   in_seq  = &ctx->vinyl.pending.seq[ free_i ];
  fd_vinyl_bstream_phdr_t * in_phdr = &ctx->vinyl.pending.phdr[ free_i ];
  memcpy( in_seq,  &seq, sizeof(ulong) );
  memcpy( in_phdr, acc_hdr, sizeof(fd_vinyl_bstream_phdr_t) );
  ulong val_esz = fd_vinyl_bstream_ctl_sz( in_phdr->ctl );
  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );
  ctx->vinyl.pending.status[ free_i ]     = VINYL_LTHASH_RD_REQ_PEND;
  ctx->vinyl.pending.seq[ free_i ]        = in_seq[0];
  ctx->vinyl.pending.rd_req[ free_i ].seq = in_seq[0];
  ctx->vinyl.pending.rd_req[ free_i ].sz  = pair_sz;

  fd_vinyl_io_read( ctx->vinyl.io, &ctx->vinyl.pending.rd_req[ free_i ] );
  ctx->vinyl.pending.status[ free_i ] = VINYL_LTHASH_RD_REQ_SENT;
  ctx->vinyl.rd_req_cnt++;

  fd_vinyl_io_rd_t * rd_req =  &ctx->vinyl.pending.rd_req[ free_i ];
  while( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING )==FD_VINYL_SUCCESS ) {
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    ctx->vinyl.pending.status[ rd_req->ctx ] = VINYL_LTHASH_RD_REQ_FREE;
    ctx->vinyl.pending.seq[ rd_req->ctx ] = ULONG_MAX;
    rd_req->sz = 0UL;
    ctx->vinyl.rd_req_cnt--;
  }
  FD_TEST( !ctx->vinyl.rd_req_cnt  );
}
#else
FD_FN_UNUSED static void
handle_vinyl_lthash_request_ur( fd_snaplh_t *             ctx,
                                ulong                     seq,
                                fd_vinyl_bstream_phdr_t * acc_hdr ) {

  /* Consume as many ready requests as possible. */
  if( FD_LIKELY( !!ctx->vinyl.rd_req_cnt ) ) {
    fd_vinyl_io_rd_t * rd_req = NULL;
    while( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, 0/*non blocking*/ )==FD_VINYL_SUCCESS ) {
      handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
      rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
      rd_req->seq = ULONG_MAX;
      rd_req->sz  = 0UL;
      ctx->vinyl.rd_req_cnt--;
    }
  }

  /* Find a free slot */
  ulong free_i = ULONG_MAX;
  if( FD_LIKELY( ctx->vinyl.rd_req_cnt<VINYL_LTHASH_RD_REQ_MAX ) ) {
    for( ulong i=0UL; i<VINYL_LTHASH_RD_REQ_MAX; i++ ) {
      fd_vinyl_io_rd_t * rd_req = &ctx->vinyl.pending.rd_req[ i ];
      if( FD_UNLIKELY( rd_req_ctx_get_status( rd_req->ctx )==VINYL_LTHASH_RD_REQ_FREE ) ) {
        free_i = i;
        break;
      }
    }
  } else {
    fd_vinyl_io_rd_t * rd_req = NULL;
    FD_TEST( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING )==FD_VINYL_SUCCESS );
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    free_i      = rd_req_ctx_get_idx( rd_req->ctx );
    ctx->vinyl.rd_req_cnt--;
  }
  FD_TEST( free_i<VINYL_LTHASH_RD_REQ_MAX );

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
  ctx->vinyl.rd_req_cnt++;
}
#endif

FD_FN_UNUSED static void
handle_vinyl_lthash_request_ur_consume_all( fd_snaplh_t * ctx ) {

  while( ctx->vinyl.rd_req_cnt ) {
    fd_vinyl_io_rd_t * rd_req = NULL;
    FD_TEST( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING )==FD_VINYL_SUCCESS );
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    ctx->vinyl.rd_req_cnt--;
  }
  FD_TEST( !ctx->vinyl.rd_req_cnt  );
  for( ulong i=0UL; i<VINYL_LTHASH_RD_REQ_MAX; i++ ) {
    fd_vinyl_io_rd_t * rd_req = &ctx->vinyl.pending.rd_req[ i ];
    FD_TEST( rd_req_ctx_get_status( rd_req->ctx )==VINYL_LTHASH_RD_REQ_FREE );
  }
}

FD_FN_UNUSED static int
handle_lthash_completion( fd_snaplh_t * ctx,
                          fd_stem_context_t * stem ) {
  fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
  fd_lthash_adder_flush( ctx->adder_sub, &ctx->running_lthash_sub );
  if( fd_seq_inc( ctx->last_in_seq, 1UL )==ctx->finish_fseq ) {
    fd_lthash_sub( &ctx->running_lthash, &ctx->running_lthash_sub );
    uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
    fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
    /* TODO should this be sent in after_credit ? */
    fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
    ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
    return FD_SNAPSHOT_STATE_IDLE;
  }
  return ctx->state;
}

static void
before_credit( fd_snaplh_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  *charge_busy = 0;

  #if IO_URING_ENABLED
  if( FD_UNLIKELY( !ctx->vinyl.rd_req_cnt ) ) return;

  /* Consume as many ready requests as possible. */
  fd_vinyl_io_rd_t * rd_req = NULL;
  while( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, 0/*non blocking*/ )==FD_VINYL_SUCCESS ) {
    handle_vinyl_lthash_compute_from_rd_req( ctx, rd_req );
    rd_req->ctx = rd_req_ctx_update_status( rd_req->ctx, VINYL_LTHASH_RD_REQ_FREE );
    rd_req->seq = ULONG_MAX;
    rd_req->sz  = 0UL;
    ctx->vinyl.rd_req_cnt--;
    *charge_busy = 1;
  }
  #else
  (void)ctx;
  #endif
}

static void
handle_wh_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         seq,
                     ulong         chunk,      /* compressed input pointer */
                     ulong         sz_comp,    /* compressed input size */
                     fd_stem_context_t * stem ) {

  FD_TEST( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH );

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
        uchar const * pair = rem;
        ulong val_esz = fd_vinyl_bstream_ctl_sz( ctl );
        ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );
        rem    += pair_sz;
        rem_sz -= pair_sz;
        if( FD_LIKELY( should_hash_account( ctx ) ) ) {
          streamlined_hash( ctx, ctx->adder, &ctx->running_lthash, pair );
        }
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

  ctx->last_in_seq = seq;

  if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
    /* TODO this does not seem to happen here */
    #if IO_URING_ENABLED
    handle_vinyl_lthash_request_ur_consume_all( ctx );
    #endif
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
    #if IO_URING_ENABLED
    handle_vinyl_lthash_request_ur( ctx, seq, acc_hdr );
    #else
    handle_vinyl_lthash_request_bd( ctx, seq, acc_hdr );
    #endif
  }
  ctx->lthash_req_seen++;
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
      ulong fseq = (tspub<<32 ) | tsorig;
      ctx->finish_fseq = fseq;
      ctx->state = FD_SNAPSHOT_STATE_FINISHING;

      if( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) {
        #if IO_URING_ENABLED
        handle_vinyl_lthash_request_ur_consume_all( ctx );
        #endif
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

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH ) ) handle_wh_data_frag( ctx, in_idx, seq, chunk, sz/*sz_comp*/, stem );
  else {
    if( FD_UNLIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_VINYL_HDR ) ) handle_lv_data_frag( ctx, in_idx, chunk, sz );
    else                                                         handle_control_frag( ctx, sig, tsorig, tspub, stem );
  }

  /* Because snapwr pacing is so loose and this tile sleeps, fd_stem
     will not return flow control credits fast enough.
     So, always update fseq (consumer progress) here. */
  ulong idx = ctx->in_kind[ 0 ]==IN_KIND_SNAPWH ? 0UL : 1UL;
  fd_fseq_update( ctx->in[ idx ].seq_sync, fd_seq_inc( ctx->last_in_seq, 1UL ) );

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

  return out_cnt;
}

/* TODO seccomp needs revision here */
static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_snaplh_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snaplh_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),     sizeof(fd_snaplh_t)                                );
  void *   pair_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                          );
  void *   pair_tmp = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                          );
  #if IO_URING_ENABLED
  void *  block_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ  );
  void *  _ring_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct io_uring), sizeof(struct io_uring)                            );
  void *  uring_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_ur_align(),   fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  (void)block_mem;
  #endif
  (void)pair_mem; (void)pair_tmp;

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  /* Set up io_bd dependencies */

  char const * bstream_path = tile->snaplh.vinyl_path;
  /* Note: it would be possible to use O_DIRECT, but it would require
     VINYL_LTHASH_BLOCK_ALIGN to be 4096UL, which substantially
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

  #if IO_URING_ENABLED

  FD_LOG_NOTICE(( "using io_uring" ));
  /* Join the bstream using io_ur */
  struct io_uring * ring = _ring_mem;
  uint depth = 2 * VINYL_LTHASH_RD_REQ_MAX;
  struct io_uring_params params = {
    .flags = IORING_SETUP_CQSIZE |
              IORING_SETUP_COOP_TASKRUN |
              IORING_SETUP_SINGLE_ISSUER,
    .features = IORING_SETUP_DEFER_TASKRUN,
    .cq_entries = depth
  };
  int init_err = io_uring_queue_init_params( depth, ring, &params );
  if( FD_UNLIKELY( init_err==-EPERM ) ) {
    FD_LOG_ERR(( "missing privileges to setup io_uring" ));
  } else if( init_err<0 ) {
    FD_LOG_ERR(( "io_uring_queue_init_params failed (%i-%s)", init_err, fd_io_strerror( -init_err ) ));
  }
  FD_TEST( 0==io_uring_register_files( ring, &dev_fd, 1 ) );

  ulong align = fd_vinyl_io_ur_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = fd_vinyl_io_ur_footprint( VINYL_LTHASH_IO_SPAD_MAX );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  fd_vinyl_io_t * io = fd_vinyl_io_ur_init( uring_mem, VINYL_LTHASH_IO_SPAD_MAX, dev_fd, ring );
  FD_TEST( io );
  ctx->vinyl.io = io;
  #endif
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),     sizeof(fd_snaplh_t)                               );
  void *   pair_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                         );
  void *   pair_tmp = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_BLOCK_MAX_SZ                         );
  void *  block_mem = FD_SCRATCH_ALLOC_APPEND( l, VINYL_LTHASH_BLOCK_ALIGN, VINYL_LTHASH_RD_REQ_MAX*VINYL_LTHASH_BLOCK_MAX_SZ );

  ctx->vinyl.pair_mem = pair_mem;
  ctx->vinyl.pair_tmp = pair_tmp;

  if( FD_UNLIKELY( tile->in_cnt!=2UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt  ));

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
    } else if( FD_LIKELY( 0==strcmp( in_link->name, "snapin_wh" ) ) ) {
      ctx->in[ i ].wksp     = in_wksp->wksp;
      ctx->in[ i ].chunk0   = 0;
      ctx->in[ i ].wmark    = 0;
      ctx->in[ i ].mtu      = in_link->mtu;
      ctx->in[ i ].base     = in_link->dcache;
      ctx->in[ i ].seq_sync = tile->in_link_fseq[ i ];
      ctx->last_in_seq      = fd_fseq_query( tile->in_link_fseq[ i ] );
      ctx->in_kind[ i ]     = IN_KIND_SNAPWH;
      ctx->io_seed          = (ulong const *)fd_dcache_app_laddr_const( in_link->dcache );
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
    rd_req->dst = ((uchar*)block_mem) + i*VINYL_LTHASH_BLOCK_MAX_SZ;
  }
  ctx->vinyl.rd_req_cnt  = 0UL;

  ctx->state                   = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                    = 1;
  ctx->acc_data_sz             = 0UL;
  ctx->hash_account            = 0;
  ctx->num_hash_tiles          = fd_topo_tile_name_cnt( topo, "snaplh" );
  ctx->hash_tile_idx           = tile->kind_id;
  ctx->pairs_seen              = 0UL;
  ctx->lthash_req_seen         = 0UL;
  fd_lthash_zero( &ctx->running_lthash );
  fd_lthash_zero( &ctx->running_lthash_sub );
  FD_LOG_NOTICE(( "*** hash_tile_idx %lu out of %lu", ctx->hash_tile_idx, ctx->num_hash_tiles ));
}

/* TODO should it be 1UL ? */
#define STEM_BURST 2UL /* one control message and one malformed message or one hash result message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplh_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplh_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit

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

#undef IO_URING_ENABLED
#undef NAME
