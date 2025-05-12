#ifndef HEADER_fd_src_discof_restore_stream_fd_frag_reader_h
#define HEADER_fd_src_discof_restore_stream_fd_frag_reader_h

#include "../../../disco/stem/fd_stem.h"
#include "../../../disco/metrics/fd_metrics.h"

struct __attribute__((aligned(64))) fd_frag_reader {
  fd_frag_meta_t const * mcache;   /* local join to this in's mcache */
  uint                   depth;    /* == fd_mcache_depth( mcache ), depth of this in's cache (const) */
  uint                   idx;      /* index of this in in the list of providers, [0, in_cnt) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in is published */
  fd_frag_meta_t const * mline;    /* == mcache + fd_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits to the in */
  uint                   accum[6]; /* local diagnostic accumulators.  These are drained during in housekeeping. */
                                   /* Assumes FD_FSEQ_DIAG_{PUB_CNT,PUB_SZ,FILT_CNT,FILT_SZ,OVRNP_CNT,OVRNP_FRAG_CNT} are 0:5 */
};
typedef struct fd_frag_reader fd_frag_reader_t;

struct fd_frag_reader_consume_ctx {
  ulong                         seq_found; /* the seq num at the current mline */
  ulong                         seq_curr;  /* the seq num in the stream reader */
  fd_frag_meta_t const * mline;     /* current mline being consumed */
  ulong                         in_idx;    /* link idx being polled */
};
typedef struct fd_frag_reader_consume_ctx fd_frag_reader_consume_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_frag_reader_align( void ) {
  return alignof(fd_frag_reader_t);
}

FD_FN_CONST static inline ulong
fd_frag_reader_footprint( void ) {
  return sizeof(fd_frag_reader_t);
}

static inline void
fd_frag_reader_init( fd_frag_reader_t * reader,
                     fd_frag_meta_t const * mcache,
                     ulong *                fseq,
                     ulong                  in_idx ) {
  reader->mcache = mcache;
  reader->fseq   = fseq;
  ulong depth  = fd_mcache_depth( reader->mcache );
  if( FD_UNLIKELY( depth > UINT_MAX ) ) FD_LOG_ERR(( "in_mcache[%lu] too deep", in_idx ));
  reader->depth  = (uint)depth;
  reader->idx    = (uint)in_idx;
  reader->seq    = 0UL;
  reader->mline  = reader->mcache + fd_mcache_line_idx( reader->seq, reader->depth );

  reader->accum[0] = 0U; reader->accum[1] = 0U; reader->accum[2] = 0U;
  reader->accum[3] = 0U; reader->accum[4] = 0U; reader->accum[5] = 0U;
}

static inline fd_frag_reader_t *
fd_frag_reader_new( void *                 mem,
                    fd_frag_meta_t const * mcache,
                    ulong *                fseq,
                    ulong                  in_idx ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_frag_reader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_frag_reader_t * self = (fd_frag_reader_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_frag_reader_t), sizeof(fd_frag_reader_t) );

  fd_frag_reader_init( self, mcache, fseq, in_idx );
  return self;
}

static inline long
fd_frag_reader_poll_frag( fd_frag_reader_t *             reader,
                          ulong                            in_idx,
                          fd_frag_reader_consume_ctx_t * ctx ) {
  ctx->seq_curr   = reader->seq;
  ctx->mline      = reader->mline;
  ctx->in_idx     = in_idx;
  ctx->seq_found = fd_frag_meta_seq_query( ctx->mline );
  return fd_seq_diff( ctx->seq_curr, ctx->seq_found );
}

static inline void
fd_frag_reader_process_overrun( fd_frag_reader_t *             reader,
                                fd_frag_reader_consume_ctx_t * ctx,
                                long                             seq_diff ) {
  reader->seq = ctx->seq_curr;
  reader->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ]++;
  reader->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] += (uint)(-seq_diff);
}

static inline void
fd_frag_reader_consume_frag( fd_frag_reader_t *             reader,
                             fd_frag_reader_consume_ctx_t * ctx ) {
  /* check for overrun: when sequence number has changed */
  ulong seq_test = fd_frag_meta_seq_query( ctx->mline );
  if( FD_UNLIKELY( fd_seq_ne( seq_test, ctx->seq_found ) ) ) {
    FD_LOG_ERR(( "Overrun while reading from input %lu", ctx->in_idx ));
  }

  /* wind up for next in poll and accumulate diagnostics */
  ctx->seq_curr = fd_seq_inc( ctx->seq_curr, 1UL );
  reader->seq   = ctx->seq_curr;
  reader->mline = reader->mcache + fd_mcache_line_idx( ctx->seq_curr, reader->depth );
  reader->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ]++;
}

static inline void *
fd_frag_reader_destroy( fd_frag_reader_t * reader ) {
  fd_memset( reader, 0, sizeof(fd_frag_reader_t) );
  return (void *)reader;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_frag_reader_h */