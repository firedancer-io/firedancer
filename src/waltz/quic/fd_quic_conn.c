#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "../../util/fd_util.h"
#include "fd_quic_enum.h"
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
  ulong token_len_off;
  ulong token_off;
};
typedef struct fd_quic_conn_layout fd_quic_conn_layout_t;

/* TODO maybe introduce a separate parameter for size of pkt_meta
   pool? */
ulong
fd_quic_conn_align( void ) {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, alignof( fd_quic_pkt_meta_t ) );
  align = fd_ulong_max( align, fd_quic_stream_map_align() );
  return align;
}

static ulong
fd_quic_conn_footprint_ext( fd_quic_limits_t const * limits,
                            fd_quic_conn_layout_t *  layout ) {

  ulong inflight_pkt_cnt = limits->inflight_pkt_cnt;
  if( FD_UNLIKELY( inflight_pkt_cnt==0UL ) ) return 0UL;

  layout->stream_cnt = limits->rx_stream_cnt;
  ulong stream_id_cnt = limits->stream_id_cnt;
  if( !stream_id_cnt ) stream_id_cnt = limits->rx_stream_cnt;

  ulong off  = 0;

  off += sizeof( fd_quic_conn_t );

  /* allocate space for stream hash map */
  /* about a million seems like a decent bound, with expected values up to 20,000 */
  ulong lg = 0;
  while( lg < 20 && (1ul<<lg) < (ulong)((double)stream_id_cnt*FD_QUIC_DEFAULT_SPARSITY) ) {
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
