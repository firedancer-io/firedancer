#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"
#include "../../util/pod/fd_pod.h"
#include "../../vinyl/io/fd_vinyl_io.h"
#include "../../vinyl/io/ur/fd_vinyl_io_ur_private.h"
#include "../../vinyl/io/ur/wb_ring.h"
#include "../../vinyl/io/ur/wq_ring.h"
#include "../../vinyl/bstream/fd_vinyl_bstream.h"
#include "../../util/io_uring/fd_io_uring_setup.h"
#include "../../util/io_uring/fd_io_uring_register.h"
#include "generated/fd_snaplh_tile_seccomp.h"

#include "utils/fd_ssctrl.h"
#include "utils/fd_vinyl_admin.h"

#include <errno.h>
#include <sys/stat.h> /* fstat */
#include <fcntl.h>    /* open  */
#include <unistd.h>   /* close */

#include "../../vinyl/io/ur/fd_vinyl_io_ur.h"

/* SNAPLH_HANDHOLDING enables various expensive correctness checks */
#define SNAPLH_HANDHOLDING 0

#define NAME "snaplh"

#define IN_CNT_MAX     (2UL)
#define IN_KIND_SNAPLV (0UL)
#define IN_KIND_SNAPWH (1UL)

/* Read queue configuration */
#define RQ_DEPTH    (1024UL) /* depth of the async read queue */
#define RQ_HEAP_MAX          /* heap size of async read queue */ \
  FD_ULONG_ALIGN_UP( 16UL<<20, FD_CHUNK_ALIGN )
FD_STATIC_ASSERT(
  RQ_HEAP_MAX>=FD_VINYL_BSTREAM_BLOCK_SZ+FD_ULONG_ALIGN_UP( FD_RUNTIME_ACC_SZ_MAX, FD_VINYL_BSTREAM_BLOCK_SZ ),
  "read queue heap cannot fit a maximally-sized account"
);

/* VINYL_LTHASH_IO_SPAD_MAX is a required param for vinyl_io, but it's
   unused in this tile (only used for writes, but this tile only reads). */
#define VINYL_LTHASH_IO_SPAD_MAX (4096UL)

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

/* Read queue *********************************************************/

/* Declare an arena for read descriptors */

struct rq_desc {
  fd_vinyl_io_rd_t rd[1];
  ulong prev;
  ulong next;
};
typedef struct rq_desc rq_desc_t;
FD_STATIC_ASSERT( offsetof(rq_desc_t, rd)==0UL, layout );

#define DLIST_NAME  rq_free
#define DLIST_ELE_T rq_desc_t
#include "../../util/tmpl/fd_dlist.c" /* FIXME use fd_pool.c? */

#if SNAPLH_HANDHOLDING
#undef FD_TMPL_USE_HANDHOLDING
#define FD_TMPL_USE_HANDHOLDING 1
#define SET_NAME buf_shadow
#define SET_MAX  RQ_HEAP_MAX
#include "../../util/tmpl/fd_set.c"
#endif

/* The snaplh tile does asynchronous reads via the vinyl_io API.
   The rq_ring (read queue ring) provides an allocator for read buffers.
   It takes into account that fd_vinyl_io_poll can deliver read results
   in arbitrary order. */

struct rq_ring {

  /* Descriptor free stack (free is a join into free_mem) */
  rq_free_t free[1];
  rq_desc_t arena[ RQ_DEPTH ];

  /* Completion reorder buffer (FIXME rename from wq to cq) */
  struct {
    wq_ring_t wq[1];
    wq_desc_t _desc[ RQ_DEPTH ];
  };

  /* Data allocator */
  uchar     buf[ RQ_HEAP_MAX ];
  wb_ring_t wb[1];
  ulong     data_seq1;

# if SNAPLH_HANDHOLDING
  /* Shadow tracking */
  ulong buf_shadow[ buf_shadow_word_cnt ];
# endif

};

typedef struct rq_ring rq_ring_t;

/* rq_ring_init constructs the read queue. */

static rq_ring_t *
rq_ring_init( rq_ring_t * ring ) {
  /* ring is a bit too big to just memset, partially initialize */
  FD_TEST( rq_free_join( rq_free_new( ring->free ) ) );
  FD_TEST( ring->free );
  for( ulong i=0UL; i<RQ_DEPTH; i++ ) rq_free_idx_push_tail( ring->free, i, ring->arena );
  wq_ring_init( ring->wq, 0UL, RQ_DEPTH );
  wb_ring_init( ring->wb, 0UL, RQ_HEAP_MAX );
  ring->data_seq1 = 0UL;
# if SNAPLH_HANDHOLDING
  buf_shadow_new( ring->buf_shadow );
# endif
  return ring;
}

/* rq_ring_acquire acquires a read request descriptor.  On success,
   retval is non-zero and points to a descriptor ready to be posted to
   fd_vinyl_io_read.  retval->dst points to a buffer with cache-line
   alignment (architecture-specific).  On failure (because there is no
   space for a request), returns NULL.  The failure condition lasts
   indefinitely until a few rq_ring_release calls are made. */

static fd_vinyl_io_rd_t *
rq_ring_acquire( rq_ring_t * ring,
                 ulong       sz ) {

  if( FD_UNLIKELY( sz > sizeof(ring->buf) ) ) {
    FD_LOG_CRIT(( "oversize read request (sz=%lu, buf_max=%lu)", sz, sizeof(ring->buf) ));
  }

  /* can fit metadata to track this request? */
  if( FD_UNLIKELY( rq_free_is_empty( ring->free, ring->arena ) ) ) return NULL;
  if( FD_UNLIKELY( wq_ring_is_full( ring->wq )  ) ) return NULL;

  /* can fit data into ring buffer? */
  if( FD_UNLIKELY( fd_vinyl_seq_gt( wb_ring_alloc_seq0( ring->wb, sz ), ring->wq->seq ) ) ) return NULL;
  ulong data_seq = ring->data_seq1;
  wb_ring_alloc( ring->wb, sz );
  ulong  buf_off = wb_ring_seq_to_off( ring->wb, data_seq );
  void * buf     = ring->buf + buf_off;
  ring->data_seq1 += sz;

# if SNAPLH_HANDHOLDING
  ulong overlap_bytes = buf_shadow_range_cnt( ring->buf_shadow, buf_off, buf_off+sz );
  if( FD_UNLIKELY( overlap_bytes ) ) {
    FD_LOG_ERR(( "detected aliasing buffers: buf range [%lu,%lu) is partially in use (%lu bytes in use)", buf_off, buf_off+sz, overlap_bytes ));
  }
  buf_shadow_insert_range( ring->buf_shadow, buf_off, buf_off+sz );
# endif

  /* allocate objects */
  ulong meta_seq = wq_ring_enqueue( ring->wq, ring->data_seq1 );
  fd_vinyl_io_rd_t * req = rq_free_ele_pop_tail( ring->free, ring->arena )->rd;

  /* fill in request */
  req->ctx = meta_seq;
  req->seq = 0UL; /* filled in by user */
  req->dst = buf;
  req->sz  = sz;

  return req;
}

/* rq_ring_release releases a read request descriptor, so it can be
   reused by a future acquire.  On return, the rd pointer is no longer
   valid. */

static void
rq_ring_release( rq_ring_t *        ring,
                 fd_vinyl_io_rd_t * rd ) {
  ulong meta_seq = rd->ctx;
  wq_ring_complete( ring->wq, meta_seq );

# if SNAPLH_HANDHOLDING
  ulong buf_off = (ulong)rd->dst - (ulong)ring->buf;
  FD_TEST( buf_shadow_range_cnt( ring->buf_shadow, buf_off, buf_off + rd->sz )==rd->sz );
  buf_shadow_remove_range( ring->buf_shadow, buf_off, buf_off + rd->sz );
# endif
  rq_free_ele_push_tail( ring->free, (rq_desc_t *)rd, ring->arena );
}

/* Tile context *******************************************************/

struct fd_snaplh_tile {
  uint state;
  int  full;

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

  fd_lthash_value_t   running_lthash;
  fd_lthash_value_t   running_lthash_sub;

  struct {
    int                dev_fd;
    fd_vinyl_io_t *    io;
    fd_vinyl_admin_t * admin;
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

  fd_io_uring_t ioring[1];

  rq_ring_t rq[1];
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplh_t),      sizeof(fd_snaplh_t) );
  if( tile->snaplh.io_uring_enabled ) {
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_ur_align(),  fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  } else {
    l = FD_LAYOUT_APPEND( l, fd_vinyl_io_bd_align(),  fd_vinyl_io_bd_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  }
  l = FD_LAYOUT_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( RQ_DEPTH, RQ_DEPTH ) );
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

static void
hash_add_account( fd_snaplh_t *       restrict ctx,
                  fd_lthash_adder_t * restrict adder,
                  fd_lthash_value_t * restrict running_lthash,
                  uchar const *       restrict _pair ) {
  uchar const * pair = _pair;
  fd_vinyl_bstream_phdr_t const * phdr = (fd_vinyl_bstream_phdr_t const *)pair;
  pair += sizeof(fd_vinyl_bstream_phdr_t);
  fd_account_meta_t const * meta = (fd_account_meta_t const *)pair;
  pair += sizeof(fd_account_meta_t);
  uchar const * data = pair;


  if( FD_UNLIKELY( meta->dlen > FD_RUNTIME_ACC_SZ_MAX ) ) {
    FD_LOG_ERR(( "Found unusually large account (data_sz=%u), aborting", meta->dlen ));
  }
  if( FD_UNLIKELY( !meta->lamports ) ) return;

  fd_lthash_adder_push_solana_account(
      adder,
      running_lthash,
      phdr->key.uc,
      data,
      meta->dlen,
      meta->lamports,
      !!meta->executable,
      meta->owner
  );

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

/* Async reads of duplicate accounts **********************************/

/* rmdup_completion handles a read completion of a duplicate account.
   Hashes the resulting account and returns the read buffer. */

static void
rmdup_completion( fd_snaplh_t *      ctx,
                  fd_vinyl_io_rd_t * rd_req ) {
  uchar * pair    = (uchar *)rd_req->dst;

# if SNAPLH_HANDHOLDING
  ulong const io_seed = FD_VOLATILE_CONST( *ctx->io_seed );
  ulong   seq     = rd_req->seq;
  ulong   pair_sz = rd_req->sz;
  if( FD_UNLIKELY( fd_vinyl_bstream_pair_test( io_seed, seq, (fd_vinyl_bstream_block_t *)pair, pair_sz ) ) ) {
    FD_LOG_WARNING(( "integrity check failed: bstream_seq=%lu pair_sz=%lu", seq, pair_sz ));
    FD_LOG_HEXDUMP_ERR(( "failing bstream pair", pair, pair_sz ));
  }
# endif

  hash_add_account( ctx, ctx->adder_sub, &ctx->running_lthash_sub, pair );
  rq_ring_release( ctx->rq, rd_req );
}

/* rmdup_clean processes all available read completions. */

static inline ulong
rmdup_clean( fd_snaplh_t * ctx,
             int           flags ) {
  fd_vinyl_io_rd_t * rd_req = NULL;
  while( fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, flags )==FD_VINYL_SUCCESS ) {
    rmdup_completion( ctx, rd_req );
    return 1UL;
  }
  return 0UL;
}

/* rmdup_enqueue enqueues removal of an account (identified by acc_hdr). */

static void
rmdup_enqueue( fd_snaplh_t *             ctx,
               ulong                     seq,
               fd_vinyl_bstream_phdr_t * acc_hdr ) {
  /* Spin until we can allocate a descriptor */
  ulong req_sz = fd_vinyl_bstream_pair_sz( fd_vinyl_bstream_ctl_sz( acc_hdr->ctl ) );
  fd_vinyl_io_t *    io     = ctx->vinyl.io;
  fd_vinyl_io_rd_t * rd_req = NULL;
  for(;;) {
    rd_req = rq_ring_acquire( ctx->rq, req_sz );
    if( FD_LIKELY( rd_req ) ) break;
    rmdup_clean( ctx, FD_VINYL_IO_FLAG_BLOCKING );
  }

  /* Fixup io addressable range */
  io->seq_past    = fd_ulong_align_dn( seq,        FD_VINYL_BSTREAM_BLOCK_SZ );
  io->seq_present = fd_ulong_align_up( seq+req_sz, FD_VINYL_BSTREAM_BLOCK_SZ );
  if( io->type==FD_VINYL_IO_TYPE_UR ) {
    fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io;
    ur->seq_clean = ur->seq_cache = ur->seq_write = io->seq_present;
  }

  /* Fill in the details */
  rd_req->seq = seq;
  rd_req->sz  = req_sz;
  fd_vinyl_io_read( ctx->vinyl.io, rd_req );
}

/* rmdup_flush flushes the 'remove duplicate accounts' queue.  This
   entails waiting for all read completions, then hashing all the
   resulting accounts. */

static void
rmdup_flush( fd_snaplh_t * ctx ) {
  for(;;) {
    fd_vinyl_io_rd_t * rd_req = NULL;
    int poll_err = fd_vinyl_io_poll( ctx->vinyl.io, &rd_req, FD_VINYL_IO_FLAG_BLOCKING );
    if( poll_err==FD_VINYL_ERR_EMPTY ) break;
    if( FD_UNLIKELY( poll_err!=FD_VINYL_SUCCESS ) ) {
      FD_LOG_ERR(( "fd_vinyl_io_poll failed (%i-%s)", poll_err, fd_vinyl_strerror( poll_err ) ));
    }
    rmdup_completion( ctx, rd_req );
  }
}

/* handle_lthash_completion finalizes the LtHash computation process. */

static uint
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

/* before_credit runs every run loop iteration. */

static void
before_credit( fd_snaplh_t *       ctx,
               fd_stem_context_t * stem FD_PARAM_UNUSED,
               int *               charge_busy ) {
  *charge_busy = !!rmdup_clean( ctx, 0 );
}

/* handle_wh_data_frag hashes accounts 'on-the-fly' as they are being
   appended to the database log file. */

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
          hash_add_account( ctx, ctx->adder, &ctx->running_lthash, rem );
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

/* handle_lv_data_frag handles account duplicates.  Whenever an account
   is replaced, this method gets called with a file pointer to the
   account being replaced (acc_hdr).

   This method then enqueues an asynchronous read.  Read completions and
   hashing is handled in before_credit. */

static void
handle_lv_data_frag( fd_snaplh_t * ctx,
                     ulong         in_idx,
                     ulong         chunk ) { /* compressed input pointer */
  if( FD_LIKELY( should_process_lthash_request( ctx ) ) ) {
    uchar const * indata = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
    ulong seq;
    fd_vinyl_bstream_phdr_t acc_hdr[1];
    memcpy( &seq,    indata, sizeof(ulong) );
    memcpy( acc_hdr, indata + sizeof(ulong), sizeof(fd_vinyl_bstream_phdr_t) );
    rmdup_enqueue( ctx, seq, acc_hdr );
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
        rmdup_flush( ctx );
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
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)sz; (void)ctl;
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SNAPWH ) )          handle_wh_data_frag( ctx, in_idx, chunk, tsorig, stem );
  else if( FD_UNLIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB_META_BATCH ) ) handle_lv_data_frag( ctx, in_idx, chunk );
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

  if( FD_LIKELY( ctx->ioring->ioring_fd>=0 ) ) {
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
                      void *        io_mem,
                      int           dev_fd ) {
  fd_io_uring_params_t params[1];
  fd_io_uring_params_init( params, RQ_DEPTH );

  if( FD_UNLIKELY( !fd_io_uring_init_shmem( ctx->ioring, params, uring_shmem, RQ_DEPTH, RQ_DEPTH ) ) ) {
    FD_LOG_ERR(( "fd_io_uring_init_shmem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_io_uring_t * ioring = ctx->ioring;

  if( FD_UNLIKELY( fd_io_uring_register_files( ioring->ioring_fd, &dev_fd, 1 )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_files failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_io_uring_restriction_t res[3] = {
    { .opcode    = FD_IORING_RESTRICTION_SQE_OP,
      .sqe_op    = IORING_OP_READ },
    { .opcode    = FD_IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
      .sqe_flags = IOSQE_FIXED_FILE },
    { .opcode    = FD_IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
      .sqe_flags = 0 }
  };
  if( FD_UNLIKELY( fd_io_uring_register_restrictions( ioring->ioring_fd, res, 3U )<0 ) ) {
    FD_LOG_ERR(( "io_uring_register_restrictions failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fd_io_uring_enable_rings( ioring->ioring_fd )<0 ) ) {
    FD_LOG_ERR(( "io_uring_enable_rings failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_vinyl_io_t * io = fd_vinyl_io_ur_init( io_mem, VINYL_LTHASH_IO_SPAD_MAX, dev_fd, ioring );
  if( FD_UNLIKELY( !io ) ) FD_LOG_ERR(( "vinyl_io_ur_init failed" ));
  return io;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplh_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplh_t),      sizeof(fd_snaplh_t)                                );
  void * io_mem;
  if( tile->snaplh.io_uring_enabled ) {
    io_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_ur_align(),    fd_vinyl_io_ur_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  } else {
    io_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_vinyl_io_bd_align(),    fd_vinyl_io_bd_footprint(VINYL_LTHASH_IO_SPAD_MAX) );
  }
  void * uring_shmem = FD_SCRATCH_ALLOC_APPEND( l, fd_io_uring_shmem_align(), fd_io_uring_shmem_footprint( RQ_DEPTH, RQ_DEPTH ) );

  /* Wait for database file to get created */

  ulong vinyl_admin_obj_id = fd_pod_query_ulong( topo->props, "vinyl_admin", ULONG_MAX );
  FD_TEST( vinyl_admin_obj_id!=ULONG_MAX );
  fd_vinyl_admin_t * vinyl_admin = fd_vinyl_admin_join( fd_topo_obj_laddr( topo, vinyl_admin_obj_id ) );
  FD_TEST( vinyl_admin );
  ctx->vinyl.admin = vinyl_admin;
  for(;;) {
    ulong vinyl_admin_status = fd_vinyl_admin_ulong_query( &vinyl_admin->status );
    if( FD_LIKELY( vinyl_admin_status!=FD_VINYL_ADMIN_STATUS_INIT_PENDING &&
                   vinyl_admin_status!=FD_VINYL_ADMIN_STATUS_ERROR ) ) break;
    fd_log_sleep( (long)1e6 /*1ms*/ );
    FD_SPIN_PAUSE();
  }

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

  ctx->vinyl.dev_fd = dev_fd;

  ctx->vinyl.io = NULL;
  ctx->ioring->ioring_fd = -1;

  if( FD_LIKELY( tile->snaplh.io_uring_enabled ) ) {
    ctx->vinyl.io = snaplh_io_uring_init( ctx, uring_shmem, io_mem, dev_fd );
  } else {
    ctx->vinyl.io = fd_vinyl_io_bd_init( io_mem, VINYL_LTHASH_IO_SPAD_MAX, dev_fd, 0, NULL, 0UL, 0UL );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snaplh_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_TEST( fd_topo_tile_name_cnt( topo, "snaplh" )<=FD_SNAPSHOT_MAX_SNAPLH_TILES );

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

  rq_ring_init( ctx->rq );
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
