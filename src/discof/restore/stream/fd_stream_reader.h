#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_reader_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_reader_h

#include "fd_frag_reader.h"
#include "../../restore/fd_restore_base.h"

struct fd_stream_reader {
  union {
    struct {
      fd_stream_frag_meta_t const * mcache;
      uint                          depth;
      uint                          idx;
      ulong                         seq;
      fd_stream_frag_meta_t const * mline;
      ulong volatile *              fseq;
      uint                          accum[6];
    };

    fd_frag_reader_t r[1]; /* FIXME strict aliasing violation on mcache */
  } base;

  ulong                  goff;
  ulong const volatile * in_sync;
};
typedef struct fd_stream_reader fd_stream_reader_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_stream_reader_align( void ) {
  return alignof(fd_stream_reader_t);
}

FD_FN_CONST static inline ulong
fd_stream_reader_footprint( void ) {
  return sizeof(fd_stream_reader_t);
}

static inline void
fd_stream_reader_init( fd_stream_reader_t *   reader,
                       fd_frag_meta_t const * mcache,
                       ulong *                fseq,
                       ulong                  in_idx  ) {
  fd_frag_reader_init( reader->base.r, mcache, fseq, in_idx );
  reader->goff = 0UL;
  reader->in_sync = fd_mcache_seq_laddr_const( reader->base.mcache->f );
}

static inline fd_stream_reader_t *
fd_stream_reader_new( void *                 mem,
                      fd_frag_meta_t const * mcache,
                      ulong *                fseq,
                      ulong                  in_idx ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stream_reader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stream_reader_t * self = (fd_stream_reader_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_reader_t), sizeof(fd_stream_reader_t) );

  fd_stream_reader_init( self, mcache, fseq, in_idx );

  return self;
}

static inline void
fd_stream_reader_reset_stream( fd_stream_reader_t * reader ) {
  reader->goff = 0UL;
}

static inline void
fd_stream_reader_update_upstream( fd_stream_reader_t * reader ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( reader->base.fseq[0] ) = reader->base.seq;
  FD_VOLATILE( reader->base.fseq[1] ) = reader->goff;
  FD_COMPILER_MFENCE();

  ulong volatile * metrics = fd_metrics_link_in( fd_metrics_base_tl, reader->base.idx );

  uint * accum = reader->base.accum;
  ulong a0 = accum[0]; ulong a1 = accum[1]; ulong a2 = accum[2];
  ulong a3 = accum[3]; ulong a4 = accum[4]; ulong a5 = accum[5];
  FD_COMPILER_MFENCE();
  metrics[0] += a0;    metrics[1] += a1;    metrics[2] += a2;
  metrics[3] += a3;    metrics[4] += a4;    metrics[5] += a5;
  FD_COMPILER_MFENCE();
  accum[0] = 0U;       accum[1] = 0U;       accum[2] = 0U;
  accum[3] = 0U;       accum[4] = 0U;       accum[5] = 0U;
}

static inline long
fd_stream_reader_poll_frag( fd_stream_reader_t *             reader,
                            ulong                            in_idx,
                            fd_frag_reader_consume_ctx_t *   ctx ) {
  return fd_frag_reader_poll_frag( reader->base.r, in_idx, ctx );
}

static inline void
fd_stream_reader_process_overrun( fd_stream_reader_t *             reader,
                                  fd_frag_reader_consume_ctx_t *   ctx,
                                 long                              seq_diff ) {
  fd_frag_reader_process_overrun( reader->base.r, ctx, seq_diff );
}

static inline void
fd_stream_reader_consume_bytes( fd_stream_reader_t * reader,
                                ulong                bytes ) {
  reader->goff += bytes;
  reader->base.accum[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ] += (uint)bytes;
}

static inline void
fd_stream_reader_consume_frag( fd_stream_reader_t *             reader,
                               fd_frag_reader_consume_ctx_t *   ctx ) {
  fd_frag_reader_consume_frag( reader->base.r, ctx );
}


static inline void *
fd_stream_reader_delete( fd_stream_reader_t * reader ) {
  fd_frag_reader_delete( reader->base.r );
  return (void *)reader;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_reader_h */
