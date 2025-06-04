#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_writer_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_writer_h

/* fd_stream_writer.h provides an API to publish data to SPMC shared
   memory byte streams. */

#include "../fd_restore_base.h"

/* fd_stream_writer_t holds stream producer state. */

struct __attribute__((aligned(16))) fd_stream_writer {
  /* Fragment descriptor output */
  fd_stream_frag_meta_t * mcache;    /* frag producer mcache */
  ulong                   seq;       /* next sequence number */
  ulong                   depth;     /* mcache depth */

  /* Data buffer (dcache) output */
  uchar * data;           /* points to first byte of dcache data region (dcache join) */
  ulong   data_max;       /* dcache data region size */
  ulong   data_cur;       /* next dcache data offset in [0,data_sz) */
  uchar * base;           /* workspace base address */
  ulong   goff;           /* byte stream offset */

  /* This point is 16-byte aligned */

  /* Backpressure */
  ulong             cr_byte_avail; /* byte publish count before slowest consumer overrun */
  ulong             cr_frag_avail; /* frag publish count before slowest consumer overrun */
  ulong *           cons_seq;      /* cons_seq[ 2*cons_idx+i ] caches cons_fseq[ cons_idx ][i] */
  ulong volatile ** cons_fseq;     /* cons_fseq[ cons_idx ] points to consumer fseq */
  /* Each consumer reports a 'frag sequence number' and the 'stream offset' */
# define FD_STREAM_WRITER_CONS_SEQ_STRIDE 2UL

  /* Fragmentation */
  ulong frag_sz_max;      /* max data sz for each frag descriptor */

  /* Cold data */
  ulong   magic;
  ulong   cons_cnt;       /* number of consumers */
  ulong   cons_max;       /* max number of consumers */
  ulong * out_sync;       /* points to mcache 'sync' field (last published seq no) */

  /* variable length data follows */
};

typedef struct fd_stream_writer fd_stream_writer_t;

#define FD_STREAM_WRITER_MAGIC (0xFD57337717E736C0UL)

/* Forward declarations */

typedef struct fd_topo fd_topo_t;
typedef struct fd_topo_tile fd_topo_tile_t;

FD_PROTOTYPES_BEGIN

/* Constructor API ****************************************************/

/* fd_stream_writer_{align,footprint} describe a memory region suitable
   to hold a stream_writer. */

FD_FN_CONST static inline ulong
fd_stream_writer_align( void ) {
  return alignof(fd_stream_writer_t);
}

FD_FN_CONST static inline ulong
fd_stream_writer_footprint( ulong cons_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_writer_t), sizeof(fd_stream_writer_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),              cons_max*sizeof(ulong)*FD_STREAM_WRITER_CONS_SEQ_STRIDE );
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),            cons_max*sizeof(ulong *) );
  return FD_LAYOUT_FINI( l, fd_stream_writer_align() );
}

/* fd_stream_writer_new initializes the memory region at mem as a
   stream_writer object.  mcache_join is a local join to an mcache
   (frag_meta or similar pointer) to which frags will be published.
   dcache_join is a local join to a dcache into which data is written.
   Returns writer object in mem on success, and NULL on failure.  Logs
   reason for failure. */

fd_stream_writer_t *
fd_stream_writer_new( void *                  mem,
                      ulong                   cons_max,
                      fd_stream_frag_meta_t * mcache_join,
                      uchar *                 dcache_join );

/* fd_stream_writer_delete releases the memory region backing a
   stream_writer.  Returns a pointer to the memory region originally
   provided to fd_stream_writer_new. */

void *
fd_stream_writer_delete( fd_stream_writer_t * writer );

/* fd_stream_writer_new_topo constructs a stream writer for a topology
   definition.  Calls new() and register_consumer() under the hood.
   tile is the actor that will be writing stream frags in topo.
   out_link_idx is the index of the output link for that tile. */

fd_stream_writer_t *
fd_stream_writer_new_topo(
    void *                 mem,
    ulong                  cons_max,
    fd_topo_t const *      topo,
    fd_topo_tile_t const * tile,
    ulong                  out_link_idx
);

static inline fd_stream_writer_t *
fd_stream_writer_join( void * _writer ) {
  fd_stream_writer_t * writer = _writer;
  if( FD_UNLIKELY( !writer ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)writer, fd_stream_writer_align() ) ) ) return NULL;
  if( FD_UNLIKELY( writer->magic!=FD_STREAM_WRITER_MAGIC ) ) return NULL;
  return writer;
}

/* Control API ********************************************************/

/* fd_stream_writer_register_consumer registers a consumer of the
   stream to the writer.  fseq_join is a local join to that consumer's
   fseq (points to the fseq's seq[0] field).  Future backpressure checks
   will include this consumer.  Returns a pointer to this consumer's
   seq cache field, or NULL on if cons_max exceeded (logs warning). */

ulong *
fd_stream_writer_register_consumer(
    fd_stream_writer_t * writer,
    ulong *              fseq_join
);

/* fd_stream_writer_notify sends an empty frag with user-specified ctl bits. */

static inline void
fd_stream_writer_notify( fd_stream_writer_t * writer,
                         ulong                ctl ) {
  fd_mcache_publish_stream( writer->mcache,
                            writer->depth,
                            writer->seq,
                            0UL,
                            0UL,
                            0UL,
                            ctl );
  writer->seq = fd_seq_inc( writer->seq, 1UL );
  writer->cr_frag_avail -= 1;
}

/* Flow control API ***************************************************/

/* fd_stream_writer_set_frag_sz_max puts an upper bound on the fragment
   sizes produced to the stream.  This helps reduce latency. */

void
fd_stream_writer_set_frag_sz_max( fd_stream_writer_t * writer,
                                  ulong                frag_sz_max );

/* fd_stream_writer_receive_flow_control_credits updates cached consumer
   progress from the consumers' fseq objects.

   FIXME Provide an API to round-robin update ins temporally spaced apart */

static inline void
fd_stream_writer_receive_flow_control_credits( fd_stream_writer_t * writer ) {
  ulong const stride = FD_STREAM_WRITER_CONS_SEQ_STRIDE;
  for( ulong i=0UL; i<writer->cons_cnt; i++ ) {
    /* FIXME could be SSE aligned copy */
    FD_COMPILER_MFENCE();
    writer->cons_seq[ stride*i   ] = FD_VOLATILE_CONST( writer->cons_fseq[ i ][0] );
    writer->cons_seq[ stride*i+1 ] = FD_VOLATILE_CONST( writer->cons_fseq[ i ][1] );
    FD_COMPILER_MFENCE();
  }
}

/* fd_stream_writer_calculate_backpressure updates fragment and stream
   backpressure from cached consumer progress. */

static inline void
fd_stream_writer_calculate_backpressure( fd_stream_writer_t * writer ) {
  ulong const cr_byte_max = writer->data_max;
  ulong const cr_frag_max = writer->depth;

  ulong cr_byte_avail = ULONG_MAX;
  ulong cr_frag_avail = ULONG_MAX;
  ulong const stride = FD_STREAM_WRITER_CONS_SEQ_STRIDE;
  for( ulong cons_idx=0UL; cons_idx<writer->cons_cnt; cons_idx++ ) {
    ulong cons_cr_byte_avail = (ulong)fd_long_max( (long)cr_byte_max-fd_long_max( fd_seq_diff( writer->goff, writer->cons_seq[ stride*cons_idx+1 ] ), 0L ), 0L );
    ulong cons_cr_frag_avail = (ulong)fd_long_max( (long)cr_frag_max-fd_long_max( fd_seq_diff( writer->seq,  writer->cons_seq[ stride*cons_idx   ] ), 0L ), 0L );
    cr_byte_avail = fd_ulong_min( cons_cr_byte_avail, cr_byte_avail );
    cr_frag_avail = fd_ulong_min( cons_cr_frag_avail, cr_frag_avail );
  }

  writer->cr_byte_avail = cr_byte_avail;
  writer->cr_frag_avail = cr_frag_avail;
}

/* In-place publish API ************************************************

   Example usage:

     void * p  = fd_stream_writer_prepare( w );
     ulong  sz = fd_stream_writer_publish_sz_max( w )
     fd_memcpy( p, src, sz );
     src += sz;
     fd_stream_writer_publish( w, sz ); */

/* fd_stream_writer_prepare prepares the caller for a frag publish.
   Returns a pointer to a memory region of publish_sz_max() bytes, into
   which the caller can write data.  A subsequent publish() call makes
   the data visible to consumers.  U.B. return value if
   publish_sz_max()==0. */

static inline void *
fd_stream_writer_prepare( fd_stream_writer_t * writer ) {
  if( FD_UNLIKELY( writer->data_cur > writer->data_max ) ) {
    FD_LOG_CRIT(( "Out-of-bounds data_cur (data_cur=%lu data_max=%lu)", writer->data_cur, writer->data_max ));
    return 0;
  }
  return writer->data + writer->data_cur;
}

/* fd_stream_writer_publish_sz_max returns the max amount of bytes that
   can be published in the next fragment. */

static inline ulong
fd_stream_writer_publish_sz_max( fd_stream_writer_t * writer ) {
  ulong const data_backp = writer->cr_byte_avail;
  ulong const frag_backp = fd_ulong_if( !!writer->cr_frag_avail, writer->frag_sz_max, 0UL );
  ulong const buf_avail  = writer->data_max - writer->data_cur;
  return fd_ulong_min( fd_ulong_min( data_backp, frag_backp ), buf_avail );
}

/* fd_stream_writer_publish completes a publish operation.  Writes a
   fragment descriptor out to the mcache if frag_sz>0. */

static inline void
fd_stream_writer_publish( fd_stream_writer_t * writer,
                          ulong                frag_sz,
                          ulong                ctl ) {
  if( FD_UNLIKELY( !frag_sz ) ) return;

  uchar * const data = writer->data + writer->data_cur;
  ulong   const loff = (ulong)data - (ulong)writer->base;

  fd_mcache_publish_stream(
      writer->mcache,
      writer->depth,
      writer->seq,
      writer->goff,
      loff,
      frag_sz,
      ctl
  );

  /* Advance fragment descriptor stream */
  writer->seq = fd_seq_inc( writer->seq, 1UL );
  writer->cr_frag_avail -= 1;

  /* Advance buffer */
  writer->data_cur      += frag_sz;
  writer->goff          += frag_sz;
  writer->cr_byte_avail -= frag_sz;
  if( FD_UNLIKELY( writer->data_cur > writer->data_max ) ) {
    FD_LOG_CRIT(( "Out-of-bounds data_cur (data_cur=%lu data_max=%lu)", writer->data_cur, writer->data_max ));
    return;
  }
  if( writer->data_cur == writer->data_max ) {
    writer->data_cur = 0UL; /* cmov */
  }
}

/* Copy publish API ***************************************************/

/* fd_stream_writer_copy publishes the given chunk to the stream as a
   sequence of stream frags.  data points to the first byte of the chunk
   to send.  data_sz is the number of bytes (<=copy_max()).
   ctl specifies how to set the 'ctl' field.  All ctl bits are copied as
   is, except for 'som' and 'eom', which act as a mask:
   Use 'fd_frag_meta_ctl( ..., som=1, eom=1, ... )' to set the 'som'
   bit on the first frag and the 'eom' bit on the last flag.  Pass
   'fd_frag_meta_ctl( ..., som=0, eom=0, ... )' or just '0UL' to leave
   fragmentation bits cleared on published frags.  */

void
fd_stream_writer_copy( fd_stream_writer_t * writer,
                       void const *         data,
                       ulong                data_sz,
                       ulong                ctl );

static inline ulong
fd_stream_writer_copy_max( fd_stream_writer_t * writer ) {
  ulong const data_backp = writer->cr_byte_avail;
  ulong const frag_backp = fd_ulong_sat_mul( writer->cr_frag_avail, writer->frag_sz_max );
  ulong const buf_avail  = writer->data_max - writer->data_cur;
  return fd_ulong_min( fd_ulong_min( data_backp, frag_backp ), buf_avail );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_writer_h */
