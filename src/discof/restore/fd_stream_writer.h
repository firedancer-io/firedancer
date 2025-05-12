#ifndef HEADER_fd_src_discof_restore_fd_stream_writer_h
#define HEADER_fd_src_discof_restore_fd_stream_writer_h

#include "../../util/fd_util_base.h"
#include "fd_restore_base.h"
#include "../../disco/topo/fd_topo.h"

/* A shared stream has a single producer and multiple consumers.
   fd_stream_writer implements the producer APIs of the shared stream */
struct fd_stream_writer {
  fd_stream_frag_meta_t * out_mcache;    /* frag producer mcache */

  uchar *                 buf;           /* laddr of shared dcache buffer */

  /* dcache buffer state */
  ulong                   buf_off;       /* local write offset into dcache buffer */
  ulong                   buf_sz;        /* dcache buffer size */
  ulong                   goff;          /* global offset into byte stream */
  ulong                   read_max;      /* max chunk size */
  ulong                   stream_off;    /* start of published stream */
  ulong                   out_seq;       /* current sequence number */

  /* flow control */
  ulong                   cr_byte_avail; /* bytes available in the slowest consumer */
  ulong                   cr_frag_avail; /* frags available in the slowest consumer */
  ulong                   cr_byte_max;   /* max dcache buffer credits (size of dcache buffer)*/
  ulong                   cr_frag_max;   /* max mcache frag credits */
  ulong                   burst_byte;
  ulong                   burst_frag;
  ulong                   cons_cnt;      /* number of consumers */
  ulong *                 cons_seq;      /* consumer fseq values */
  ulong **                cons_fseq;     /* consumer fseq pointers */
};
typedef struct fd_stream_writer fd_stream_writer_t;

#define EXPECTED_FSEQ_CNT_PER_CONS 2

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_stream_writer_align( void ) {
  return alignof(fd_stream_writer_t);
}

FD_FN_CONST static inline ulong
fd_stream_writer_footprint( void ) {
  return sizeof(fd_stream_writer_t);
}

static inline uchar *
fd_stream_writer_get_write_ptr( fd_stream_writer_t * writer ) {
  return writer->buf + writer->buf_off;
}

fd_stream_writer_t *
fd_stream_writer_new( void *                  mem,
                      fd_topo_t *             topo,
                      fd_topo_tile_t *        tile,
                      ulong                   link_id,
                      ulong                   read_max,
                      ulong                   burst_byte,
                      ulong                   burst_frag );

static inline void
fd_stream_writer_init_flow_control_credits( fd_stream_writer_t * writer ) {
  for( ulong cons_idx=0UL; cons_idx<writer->cons_cnt; cons_idx++ ) {
    writer->cons_seq [ EXPECTED_FSEQ_CNT_PER_CONS*cons_idx   ] = FD_VOLATILE_CONST( writer->cons_fseq[ cons_idx ][0] );
    writer->cons_seq [ EXPECTED_FSEQ_CNT_PER_CONS*cons_idx+1 ] = FD_VOLATILE_CONST( writer->cons_fseq[ cons_idx ][1] );
  }
}

static inline void
fd_stream_writer_receive_flow_control_credits( fd_stream_writer_t * writer,
                                               ulong                cons_idx) {
  FD_COMPILER_MFENCE();
  writer->cons_seq [ EXPECTED_FSEQ_CNT_PER_CONS*cons_idx   ] = FD_VOLATILE_CONST( writer->cons_fseq[ cons_idx ][0] );
  writer->cons_seq [ EXPECTED_FSEQ_CNT_PER_CONS*cons_idx+1 ] = FD_VOLATILE_CONST( writer->cons_fseq[ cons_idx ][1] );
  FD_COMPILER_MFENCE();
}

static inline void
fd_stream_writer_update_flow_control_credits( fd_stream_writer_t * writer,
                                              ulong * slowest_cons_out ) {
  ulong slowest_cons = ULONG_MAX;
  if( FD_LIKELY( writer->cr_byte_avail<writer->cr_byte_max || writer->cr_frag_avail<writer->cr_frag_max ) ) {
    ulong cr_byte_avail = writer->cr_byte_max;
    ulong cr_frag_avail = writer->cr_frag_max;
    for( ulong cons_idx=0UL; cons_idx<writer->cons_cnt; cons_idx++ ) {
      ulong cons_cr_byte_avail = (ulong)fd_long_max( (long)writer->cr_byte_max-fd_long_max( fd_seq_diff( writer->goff, writer->cons_seq[ 2*cons_idx+1 ] ), 0L ), 0L );
      ulong cons_cr_frag_avail = (ulong)fd_long_max( (long)writer->cr_frag_max-fd_long_max( fd_seq_diff( writer->out_seq,   writer->cons_seq[ 2*cons_idx   ] ), 0L ), 0L );
      slowest_cons  = fd_ulong_if( cons_cr_byte_avail<cr_byte_avail, cons_idx, slowest_cons );
      cr_byte_avail = fd_ulong_min( cons_cr_byte_avail, cr_byte_avail );
      cr_frag_avail = fd_ulong_min( cons_cr_frag_avail, cr_frag_avail );
    }

    writer->cr_byte_avail = cr_byte_avail;
    writer->cr_frag_avail = cr_frag_avail;
  }

  if( slowest_cons_out ) {
    *slowest_cons_out = slowest_cons;
  }
}

static inline ulong
fd_stream_writer_get_avail_bytes( fd_stream_writer_t * writer ) {
  if( FD_UNLIKELY( writer->buf_off > writer->buf_sz ) ) {
    FD_LOG_CRIT(( "Buffer overflow (buf_off=%lu buf_sz=%lu)", writer->buf_off, writer->buf_sz ));
    return 0;
  }

  ulong const read_max = fd_ulong_min( writer->cr_byte_avail, writer->read_max );
  return fd_ulong_min( read_max, writer->buf_sz - writer->buf_off );
}

static inline void
fd_stream_writer_publish( fd_stream_writer_t * writer,
                          ulong                frag_sz ) {
  ulong loff = writer->stream_off;
  fd_mcache_publish_stream( writer->out_mcache,
                            fd_mcache_depth( writer->out_mcache->f ),
                            writer->out_seq,
                            writer->goff,
                            loff,
                            frag_sz,
                            0 );
  writer->out_seq = fd_seq_inc( writer->out_seq, 1UL );
  writer->cr_frag_avail -= 1;

  /* rewind buf_off to start of buffer */
  if( writer->buf_off >= writer->buf_sz ) {
    writer->buf_off = 0UL;
  }

  writer->stream_off = writer->buf_off;
}

static inline void
fd_stream_writer_advance( fd_stream_writer_t * writer,
                          ulong                sz ) {
  writer->goff          += sz;
  writer->buf_off       += sz;
  writer->cr_byte_avail -= sz;
}

/* TODO: destroy / free */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_stream_writer_h */
