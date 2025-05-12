#ifndef HEADER_fd_src_discof_restore_fd_stream_reader_h
#define HEADER_fd_src_discof_restore_fd_stream_reader_h

#include "fd_restore_base.h"
#include "fd_frag_reader.h"

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

    fd_frag_reader_t r[1];
  } base;
  ulong goff;
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
fd_stream_reader_init( fd_stream_reader_t * reader,
                       fd_frag_meta_t const * mcache,
                       ulong *                fseq,
                       ulong                  in_idx  ) {
  fd_frag_reader_init( reader->base.r, mcache, fseq, in_idx );
  reader->goff = 0UL;
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

static inline long
fd_stream_reader_poll_frag( fd_stream_reader_t *             reader,
                            ulong                            in_idx,
                            fd_frag_reader_consume_ctx_t *   ctx ) {
  return fd_frag_reader_poll_frag( reader->base.r, in_idx, ctx );
}

static inline void
fd_stream_reader_process_overrun( fd_stream_reader_t *             reader,
                                  fd_frag_reader_consume_ctx_t * ctx,
                                 long                             seq_diff ) {
  fd_frag_reader_process_overrun( reader->base.r, ctx, seq_diff );
}

static inline void
fd_stream_reader_consume_frag( fd_stream_reader_t *             reader,
                               fd_frag_reader_consume_ctx_t * ctx,
                               ulong                            frag_sz ) {
  reader->goff += frag_sz;
  fd_frag_reader_consume_frag( reader->base.r, ctx, frag_sz );
}

static inline void *
fd_stream_reader_destroy( fd_stream_reader_t * reader ) {
  fd_frag_reader_destroy( reader->base.r );
  reader->goff = 0UL;
  return (void *)reader;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_stream_reader_h */
