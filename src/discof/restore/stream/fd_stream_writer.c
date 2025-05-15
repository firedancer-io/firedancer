#include "fd_stream_writer.h"
#include "../../../util/log/fd_log.h"
#include "../../../tango/dcache/fd_dcache.h"

fd_stream_writer_t *
fd_stream_writer_new( void *                  mem,
                      fd_topo_t *             topo,
                      fd_topo_tile_t *        tile,
                      ulong                   link_id,
                      ulong                   burst_byte,
                      ulong                   burst_frag ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stream_writer_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stream_writer_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_writer_t), sizeof(fd_stream_writer_t) );

  fd_topo_link_t const * link        = &topo->links[ tile->out_link_id[ link_id ] ];
  void * dcache                      = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ link_id ] ].dcache_obj_id ) );
  fd_stream_frag_meta_t * out_mcache = fd_type_pun( topo->links[ tile->out_link_id[ link_id ] ].mcache );
  ulong cons_cnt                     = fd_topo_link_reliable_consumer_cnt( topo, link );

  self->out_mcache = out_mcache;
  self->buf           = dcache;
  self->buf_base      = (ulong)dcache - (ulong)fd_wksp_containing( dcache );
  self->buf_off       = 0UL;
  self->buf_sz        = fd_dcache_data_sz( dcache );
  self->goff          = 0UL;
  self->read_max      = 0UL; /* this should be set by the tile via fd_stream_writer_set_read_max */
  self->stream_off    = 0UL;
  self->goff_start    = 0UL;
  self->out_seq       = 0UL;

  /* Set up flow control state */
  self->cr_byte_avail = 0UL;
  self->cr_frag_avail = 0UL;
  self->cr_byte_max   = fd_dcache_data_sz( dcache );
  self->cr_frag_max   = fd_mcache_depth( self->out_mcache->f );
  self->burst_byte    = burst_byte;
  self->burst_frag    = burst_frag;
  self->cons_cnt      = cons_cnt;
  self->cons_seq      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), EXPECTED_FSEQ_CNT_PER_CONS*cons_cnt*sizeof(ulong) );
  self->cons_fseq     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *), cons_cnt*sizeof(ulong *) );
  self->out_sync      = fd_mcache_seq_laddr( topo->links[ tile->out_link_id[ link_id ] ].mcache );

  /* Set up consumer fseq pointer array.
     We keep track of 2 fseqs per consumer to manage stream flow control.
     The first fseq tracks the consumer's mcache sequence number.
     The second fseq tracks the consumer's global read offset into stream. */
  ulong cons_idx = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ link_id ] && consumer_tile->in_link_reliable[ j ] ) ) {
        self->cons_fseq[ cons_idx ] = consumer_tile->in_link_fseq[ j ];
        if( FD_UNLIKELY( !self->cons_fseq[ cons_idx ] ) ) {
          FD_LOG_ERR(( "NULL cons_fseq[%lu] for out_link=%lu", cons_idx, tile->out_link_id[ link_id ] ));
        }
        cons_idx++;
      }
    }
  }

  fd_memset(self->cons_seq, 0, EXPECTED_FSEQ_CNT_PER_CONS*cons_cnt*sizeof(ulong) );
  /* make sure we're not tripping */
  FD_TEST( cons_idx==cons_cnt );

  return self;
}
