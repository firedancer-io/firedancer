#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "../../util/fd_util.h"
#include "fd_quic_pkt_meta.h"
#include "fd_quic_private.h"

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

  /* initial stream count not allowed to be larger than max stream count limit */
  if( FD_UNLIKELY( limits->initial_stream_cnt[0] > limits->stream_cnt[0] ) ) return 0UL;
  if( FD_UNLIKELY( limits->initial_stream_cnt[1] > limits->stream_cnt[1] ) ) return 0UL;
  if( FD_UNLIKELY( limits->initial_stream_cnt[2] > limits->stream_cnt[2] ) ) return 0UL;
  if( FD_UNLIKELY( limits->initial_stream_cnt[3] > limits->stream_cnt[3] ) ) return 0UL;

  stream_cnt = layout->stream_cnt = limits->stream_pool_cnt;

  ulong off  = 0;

  off += sizeof( fd_quic_conn_t );

  /* allocate space for stream hash map */
  /* about a million seems like a decent bound, with expected values up to 20,000 */
  ulong lg = 0;
  while( lg < 20 && (1ul<<lg) < (ulong)((double)stream_cnt*stream_sparsity) ) {
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

  conn->quic  = quic;
  conn->state = FD_QUIC_CONN_STATE_INVALID;

  /* Initialize streams */

  FD_QUIC_STREAM_LIST_SENTINEL( conn->send_streams );
  FD_QUIC_STREAM_LIST_SENTINEL( conn->used_streams );

  /* Initialize stream hash map */

  ulong stream_map_laddr = (ulong)mem + layout.stream_map_off;
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


/* set the max concurrent streams value for the specified type
   This is used to flow control the peer.

   type is one of:
     FD_QUIC_TYPE_UNIDIR
     FD_QUIC_TYPE_BIDIR */
FD_QUIC_API void
fd_quic_conn_set_max_streams( fd_quic_conn_t * conn, uint dirtype, ulong stream_cnt ) {
  if( FD_UNLIKELY( dirtype != FD_QUIC_TYPE_UNIDIR
                && dirtype != FD_QUIC_TYPE_BIDIR ) ) {
    FD_LOG_ERR(( "fd_quic_conn_set_max_stream called with invalid type" ));
    return;
  }

  fd_quic_t *       quic  = conn->quic;

  /* TODO align usage of "type" and "dirtype"
     perhaps:
       dir        - direction: bidir or unidir
       role       - client or server
       type       - dir | role */
  uint peer = (uint)!conn->server;
  uint type = peer + ( (uint)dirtype << 1u );

  /* check the limit on stream_cnt */
  if( FD_UNLIKELY( stream_cnt > quic->limits.stream_cnt[type] ) ) {
    return;
  }

  /* store the desired value */
  ulong max_concur_streams = conn->max_concur_streams[type] = stream_cnt;
  ulong cur_stream_cnt     = conn->cur_stream_cnt[type];

  /* how many remain */
  ulong rem = fd_ulong_if( max_concur_streams > cur_stream_cnt,
                           max_concur_streams - cur_stream_cnt,
                           0UL );

  /* set tgt_sup_stream_id */
  conn->tgt_sup_stream_id[type] = conn->sup_stream_id[type] + ( rem << 2UL );

  /* update the weight */

  fd_quic_conn_update_weight( conn, dirtype );

  /* reassign the streams */
  fd_quic_assign_streams( conn->quic );
}


/* get the current value for the concurrent streams for the specified type

   type is one of:
     FD_QUIC_TYPE_UNIDIR
     FD_QUIC_TYPE_BIDIR */
FD_QUIC_API ulong
fd_quic_conn_get_max_streams( fd_quic_conn_t * conn, uint dirtype ) {
  uint peer = (uint)!conn->server;
  uint type = peer + ( (uint)dirtype << 1u );
  return conn->max_concur_streams[type];
}

/* update the tree weight
   called whenever weight may have changed */
void
fd_quic_conn_update_weight( fd_quic_conn_t * conn, uint dirtype ) {
  if( FD_UNLIKELY( dirtype != FD_QUIC_TYPE_UNIDIR
                && dirtype != FD_QUIC_TYPE_BIDIR ) ) {
    FD_LOG_ERR(( "fd_quic_conn_update_weight called with invalid type" ));
    return;
  }

  /* TODO align usage of "type" and "dirtype"
     perhaps:
       dir        - direction: bidir or unidir
       role       - client or server
       type       - dir | role */
  uint peer = (uint)!conn->server;
  uint type = peer + ( (uint)dirtype << 1u );

  /* get tgt_sup_stream_id, sup_stream_id */
  ulong tgt_sup_stream_id = conn->tgt_sup_stream_id[type];
  ulong sup_stream_id     = conn->sup_stream_id[type];

  /* update the cs_tree */

  /* determine the weight */

  ulong weight = fd_ulong_if( tgt_sup_stream_id > sup_stream_id,
                              ( tgt_sup_stream_id - sup_stream_id ) >> 2UL,
                              0UL );

  if( conn->state != FD_QUIC_CONN_STATE_ACTIVE &&
      conn->state != FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) {
    weight = 0;
  }

  /* set the weight in the cs_tree */
  fd_quic_cs_tree_t * cs_tree = fd_quic_get_state( conn->quic )->cs_tree;
  ulong               idx     = ( conn->conn_idx << 1UL ) + dirtype;
  fd_quic_cs_tree_update( cs_tree, idx, weight );

  /* don't assign streams here to avoid unwanted recursion */
}
