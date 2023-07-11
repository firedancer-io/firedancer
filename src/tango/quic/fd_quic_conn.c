#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "../../util/fd_util.h"
#include "fd_quic_pkt_meta.h"

/* define a map for stream_id -> stream* */
#define MAP_NAME              fd_quic_stream_map
#define MAP_KEY               stream_id
#define MAP_T                 fd_quic_stream_map_t
#define MAP_KEY_NULL          FD_QUIC_STREAM_ID_UNUSED
#define MAP_KEY_INVAL(key)    ((key)==MAP_KEY_NULL)
#define MAP_QUERY_OPT         1

#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_quic_conn_layout {
  ulong stream_cnt;
  ulong stream_ptr_off;
  ulong stream_footprint;
  ulong stream_off;
  int   stream_map_lg;
  ulong stream_map_off;
  ulong pkt_meta_off;
  ulong ack_off;
  ulong token_len_off;
  ulong token_off;
};
typedef struct fd_quic_conn_layout fd_quic_conn_layout_t;

/* TODO maybe introduce a separate parameter for size of pkt_meta
   pool? */
ulong
fd_quic_conn_align( void ) {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_ack_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_pkt_meta_t ) );
  align = fd_ulong_max( align, fd_quic_stream_map_align() );
  return align;
}

static ulong
fd_quic_conn_footprint_ext( fd_quic_limits_t const * limits,
                            fd_quic_conn_layout_t *  layout ) {

  ulong  tx_buf_sz           = limits->tx_buf_sz;
  double stream_sparsity     = limits->stream_sparsity;
  ulong  inflight_pkt_cnt    = limits->inflight_pkt_cnt;

  ulong  stream_cnt = (
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT  ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER  ] );
  layout->stream_cnt = stream_cnt;

  if( FD_UNLIKELY( stream_cnt         ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( tx_buf_sz          ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( inflight_pkt_cnt   ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( stream_sparsity==0.0 ) ) {
    stream_sparsity = FD_QUIC_DEFAULT_SPARSITY;
  }

  ulong off  = 0;

  off += sizeof( fd_quic_conn_t );

  /* allocate space for stream pointers
     FIXME: for now assuming stream cnt is same for each 4 types of streams */
  off                     = fd_ulong_align_up( off, alignof(void *) );
  layout->stream_ptr_off  = off;
  off                    += stream_cnt * sizeof(void *);

  /* allocate space for stream instances */
  ulong   stream_footprint = fd_quic_stream_footprint( tx_buf_sz );
  layout->stream_footprint = stream_footprint;

  off                 = fd_ulong_align_up( off, fd_quic_stream_align() );
  layout->stream_off  = off;
  off                += stream_cnt*stream_footprint;

  /* allocate space for stream hash map */
  ulong lg = 0;
  while( lg < 40 && (1ul<<lg) < (ulong)((double)stream_cnt*stream_sparsity) ) {
    lg++;
  }
  layout->stream_map_lg = (int)lg;

  off                     = fd_ulong_align_up( off, fd_quic_stream_align() );
  layout->stream_map_off  = off;
  off                    += fd_quic_stream_map_footprint( (int)lg );

  /* allocate space for packet metadata */
  off                   = fd_ulong_align_up( off, alignof(fd_quic_pkt_meta_t) );
  layout->pkt_meta_off  = off;
  off                  += inflight_pkt_cnt * sizeof(fd_quic_pkt_meta_t);

  /* allocate space for ACKs */
  off                   = fd_ulong_align_up( off, alignof(fd_quic_ack_t) );
  layout->ack_off       = off;
  off                  += inflight_pkt_cnt * sizeof(fd_quic_ack_t);

  /* align total footprint */

  return off;
}

FD_FN_PURE ulong
fd_quic_conn_footprint( fd_quic_limits_t const * limits ) {
  fd_quic_conn_layout_t layout;
  return fd_quic_conn_footprint_ext( limits, &layout );
}

fd_quic_conn_t *
fd_quic_conn_new( void *                   mem,
                  fd_quic_t *              quic,
                  fd_quic_limits_t const * limits ) {

  /* Argument checks */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong align = fd_quic_conn_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !quic ) ) {
    FD_LOG_WARNING(( "NULL quic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !limits ) ) {
    FD_LOG_WARNING(( "NULL limits" ));
    return NULL;
  }

  fd_quic_conn_layout_t layout = {0};
  ulong footprint = fd_quic_conn_footprint_ext( limits, &layout );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for limits" ));
    return NULL;
  }

  /* Initialize conn */

  fd_quic_conn_t * conn = (fd_quic_conn_t *)mem;
  fd_memset( conn, 0, sizeof(fd_quic_conn_t) );

  conn->quic             = quic;
  conn->stream_tx_buf_sz = limits->tx_buf_sz;
  conn->tot_num_streams  = layout.stream_cnt;
  conn->state            = FD_QUIC_CONN_STATE_INVALID;

  /* Initialize stream pointers */

  conn->streams = (fd_quic_stream_t **)( (ulong)mem + layout.stream_ptr_off );

  /* Initialize streams */

  FD_QUIC_STREAM_LIST_SENTINEL( conn->send_streams );
  FD_QUIC_STREAM_LIST_SENTINEL( conn->unused_streams );

  fd_quic_stream_t * unused_streams = conn->unused_streams;

  ulong stream_laddr = (ulong)mem + layout.stream_off;
  for( ulong j=0; j < layout.stream_cnt; j++ ) {
    fd_quic_stream_t * stream = fd_quic_stream_new(
        (void *)stream_laddr, conn, limits->tx_buf_sz );
    if( FD_UNLIKELY( !stream ) ) return NULL;

    conn->streams[j] = stream;

    /* insert into unused list */
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( unused_streams, stream );

    stream_laddr += layout.stream_footprint;
  }

  /* Initialize stream hash map */

  ulong stream_map_laddr = (ulong)mem + layout.stream_map_off;
  FD_TEST( stream_laddr <= stream_map_laddr );
  conn->stream_map = fd_quic_stream_map_join( fd_quic_stream_map_new( (void *)stream_map_laddr, layout.stream_map_lg ) );
  if( FD_UNLIKELY( !conn->stream_map ) ) return NULL;

  /* Initialize packet meta pool */

  ulong                pkt_meta_cnt = limits->inflight_pkt_cnt;
  fd_quic_pkt_meta_t * pkt_meta     = (fd_quic_pkt_meta_t *)( (ulong)mem + layout.pkt_meta_off );
  fd_memset( pkt_meta, 0, pkt_meta_cnt*sizeof(fd_quic_pkt_meta_t) );

  /* store pointer to storage and size */
  conn->pkt_meta_mem = pkt_meta;
  conn->num_pkt_meta = pkt_meta_cnt;

  /* Initialize ACKs array */

  ulong           ack_cnt = limits->inflight_pkt_cnt;
  fd_quic_ack_t * acks    = (fd_quic_ack_t *)( (ulong)mem + layout.ack_off );
  fd_memset( acks, 0, ack_cnt * sizeof(fd_quic_ack_t) );

  /* initialize free list of acks metadata */
  conn->acks_free = acks;
  for( ulong j=0; j<ack_cnt; ++j ) {
    ulong k = j + 1;
    acks[j].next =  k < ack_cnt ? acks + k : NULL;
  }

  return conn;
}

/* set the user-defined context value on the connection */
void
fd_quic_conn_set_context( fd_quic_conn_t * conn, void * context ) {
  conn->context = context;
}


/* get the user-defined context value from a connection */
void *
fd_quic_conn_get_context( fd_quic_conn_t * conn ) {
  return conn->context;
}
