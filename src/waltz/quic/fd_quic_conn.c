#include "fd_quic_conn.h"
#include "fd_quic_common.h"
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
  int   stream_map_lg;
  ulong stream_map_off;
};
typedef struct fd_quic_conn_layout fd_quic_conn_layout_t;

ulong
fd_quic_conn_align( void ) {
  ulong align = fd_ulong_max( alignof( fd_quic_conn_t ), alignof( fd_quic_stream_t ) );
  align = fd_ulong_max( align, fd_quic_stream_map_align() );
  return align;
}

static ulong
fd_quic_conn_footprint_ext( fd_quic_limits_t const * limits,
                            fd_quic_conn_layout_t *  layout ) {

  ulong stream_id_cnt = limits->stream_id_cnt;

  ulong off  = 0;

  off += sizeof( fd_quic_conn_t );

  if( stream_id_cnt ) {
    /* allocate space for stream hash map */
    /* about a million seems like a decent bound, with expected values up to 20,000 */
    ulong lg = 0;
    while( lg < 20 && (1ul<<lg) < (ulong)((double)stream_id_cnt*FD_QUIC_DEFAULT_SPARSITY) ) {
      lg++;
    }
    layout->stream_map_lg = (int)lg;

    off                     = fd_ulong_align_up( off, fd_quic_stream_map_align() );
    layout->stream_map_off  = off;
    off                    += fd_quic_stream_map_footprint( (int)lg );
  } else {
    layout->stream_map_lg  = 0;
    layout->stream_map_off = 0UL;
  }

  return fd_ulong_align_up( off, fd_quic_conn_align() );
}

ulong
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

  conn->quic     = quic;
  conn->state    = FD_QUIC_CONN_STATE_INVALID;

  quic->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_INVALID ]++;

  /* Initialize streams */

  FD_QUIC_STREAM_LIST_SENTINEL( conn->send_streams );
  FD_QUIC_STREAM_LIST_SENTINEL( conn->used_streams );

  /* Initialize stream hash map */

  if( layout.stream_map_off ) {
    ulong stream_map_laddr = (ulong)mem + layout.stream_map_off;
    conn->stream_map = fd_quic_stream_map_join( fd_quic_stream_map_new( (void *)stream_map_laddr, layout.stream_map_lg, (ulong)fd_tickcount() ) );
    if( FD_UNLIKELY( !conn->stream_map ) ) return NULL;
  }

  /* Initialize packet meta tracker */
  fd_quic_state_t * state = fd_quic_get_state( quic );
  fd_quic_pkt_meta_tracker_init( &conn->pkt_meta_tracker,
                                 quic->limits.inflight_frame_cnt,
                                 state->pkt_meta_pool );


  /* Initialize service timers */
  fd_quic_svc_timers_init_conn( conn );

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

char const *
fd_quic_conn_reason_name( uint reason ) {
  /* define mapping from reason code to name as a c-string */
  static char const * fd_quic_conn_reason_names[] = {
#   define COMMA ,
#   define _(NAME,CODE,DESC) \
    [CODE] = #NAME
    FD_QUIC_REASON_CODES(_,COMMA)
#   undef _
#   undef COMMA
  };

# define ELEMENTS ( sizeof(fd_quic_conn_reason_names) / sizeof(fd_quic_conn_reason_names[0]) )

  if( FD_UNLIKELY( reason >= ELEMENTS ) ) return "N/A";

  char const * name = fd_quic_conn_reason_names[reason];

  return name ? name : "N/A";
}

void
fd_quic_conn_validate_init( fd_quic_t * quic ) {
  fd_quic_state_t * state    = fd_quic_get_state( quic );
  ulong             conn_cnt = quic->limits.conn_cnt;
  for( ulong j=0UL; j<conn_cnt; j++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, j );
    conn->visited         = 0U;
  }
}
