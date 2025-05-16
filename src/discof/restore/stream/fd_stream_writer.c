#include "fd_stream_writer.h"
#include "../../../util/log/fd_log.h"
#include "../../../tango/dcache/fd_dcache.h"
#include "../../../disco/topo/fd_topo.h"

fd_stream_writer_t *
fd_stream_writer_new( void *                  mem,
                      ulong                   cons_max,
                      fd_stream_frag_meta_t * mcache,
                      uchar *                 dcache ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stream_writer_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stream_writer_t * writer    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_writer_t), sizeof(fd_stream_writer_t) );
  ulong *              cons_seq  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              cons_max*sizeof(ulong)*FD_STREAM_WRITER_CONS_SEQ_STRIDE );
  ulong volatile **    cons_fseq = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *),            cons_max*sizeof(ulong *) );
  FD_SCRATCH_ALLOC_FINI( l, fd_stream_writer_align() );

  fd_memset( writer, 0, sizeof(fd_stream_writer_t) );

  writer->mcache   = mcache;
  writer->out_sync = fd_mcache_seq_laddr( mcache->f );
  writer->seq      = fd_mcache_seq_query( writer->out_sync );
  writer->depth    = fd_mcache_depth( mcache->f );

  writer->data     = dcache;
  writer->data_max = fd_dcache_data_sz( dcache );
  writer->data_cur = 0UL;
  writer->base     = (uchar *)fd_wksp_containing( dcache ); /* FIXME impure */
  writer->goff     = 0UL;

  writer->cr_byte_avail = 0UL;
  writer->cr_frag_avail = 0UL;
  writer->cons_seq      = cons_seq;
  writer->cons_fseq     = cons_fseq;

  writer->frag_sz_max = writer->data_max;

  writer->cons_cnt = 0UL;
  writer->cons_max = cons_max;
  /* writer->out_sync already set */

  FD_COMPILER_MFENCE();
  writer->magic = FD_STREAM_WRITER_MAGIC;
  return writer;
}

void *
fd_stream_writer_delete( fd_stream_writer_t * writer ) {
  fd_memset( writer, 0, sizeof(fd_stream_writer_t) );
  return writer;
}

ulong *
fd_stream_writer_register_consumer(
    fd_stream_writer_t * writer,
    ulong *              fseq_join
) {
  if( FD_UNLIKELY( writer->cons_cnt >= writer->cons_max ) ) {
    FD_LOG_WARNING(( "Can't register consumer, cons_max %lu exceeded", writer->cons_max ));
    return NULL;
  }

  ulong const cons_idx = writer->cons_cnt++;
  ulong * seq = writer->cons_seq + ( cons_idx*FD_STREAM_WRITER_CONS_SEQ_STRIDE );
  writer->cons_fseq[ cons_idx ] = fd_type_pun( fseq_join );
  seq[ 0 ] = FD_VOLATILE_CONST( fseq_join[ 0 ] );
  seq[ 1 ] = FD_VOLATILE_CONST( fseq_join[ 1 ] );
  return seq;
}

fd_stream_writer_t *
fd_stream_writer_new_topo(
    void *                 mem,
    ulong                  cons_max,
    fd_topo_t const *      topo,
    fd_topo_tile_t const * tile,
    ulong                  out_link_idx
) {
  ulong const             out_link_id = tile->out_link_id[ out_link_idx ];
  fd_topo_link_t const *  out_link    = &topo->links[ out_link_id ];
  fd_stream_frag_meta_t * mcache      = fd_type_pun( out_link->mcache );
  void *                  dcache      = fd_dcache_join( fd_topo_obj_laddr( topo, out_link->dcache_obj_id ) );
  ulong                   cons_cnt    = fd_topo_link_reliable_consumer_cnt( topo, out_link );
  if( FD_UNLIKELY( !mcache ) ) {
    FD_LOG_WARNING(( "NULL mcache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !dcache ) ) {
    FD_LOG_WARNING(( "NULL dcache" ));
    return NULL;
  }
  if( FD_UNLIKELY( cons_cnt>cons_max ) ) {
    FD_LOG_WARNING(( "cons_cnt is %lu but cons_max is only %lu", cons_cnt, cons_max ));
  }

  fd_stream_writer_t * writer = fd_stream_writer_new( mem, cons_max, mcache, dcache );
  if( FD_UNLIKELY( !writer ) ) return NULL; /* logs warning */

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      if( consumer_tile->in_link_id[ j ]!=out_link_id ) continue;
      if( !consumer_tile->in_link_reliable[ j ] ) continue;

      ulong * fseq = consumer_tile->in_link_fseq[ j ];
      if( FD_UNLIKELY( !fseq ) ) {
        FD_LOG_WARNING(( "NULL fseq for consumer tile=%s:%lu in_link_idx=%lu",
                          consumer_tile->name, consumer_tile->kind_id, j ));
      }
      if( FD_UNLIKELY( !fd_stream_writer_register_consumer( writer, fseq ) ) ) {
        return NULL; /* logs warning */
      }
    }
  }

  return writer;
}

void
fd_stream_writer_set_frag_sz_max( fd_stream_writer_t * writer,
                                  ulong                frag_sz_max ) {
  writer->frag_sz_max = fd_ulong_min( writer->data_max, frag_sz_max );
}

void
fd_stream_writer_copy( fd_stream_writer_t * writer,
                       void const *         data,
                       ulong                data_sz,
                       ulong const          ctl_mask ) {
  if( FD_UNLIKELY( ( data_sz > writer->cr_byte_avail ) |
                   ( data_sz > writer->data_max      ) ) ) {
    FD_LOG_ERR(( "invalid data_sz %lu (cr_byte_avail=%lu data_max=%lu)",
                  data_sz, writer->cr_byte_avail, writer->data_max ));
  }

  ulong const frag_sz_max = writer->frag_sz_max;
  int som = 1;
  for(;;) {
    ulong const op_sz   = fd_ulong_min( data_sz, frag_sz_max );
    ulong const next_sz = data_sz-op_sz;
    int   const eom     = next_sz==0UL;
    ulong const ctl     = ctl_mask & fd_frag_meta_ctl( FD_FRAG_META_ORIG_MAX-1, som, eom, 1 );

    fd_memcpy( fd_stream_writer_prepare( writer ), data, op_sz );
    fd_stream_writer_publish( writer, op_sz, ctl );

    som     = 0;
    data_sz = next_sz;
  }
}
