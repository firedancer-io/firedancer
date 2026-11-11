#include "fd_quic_conn.h"
#include "fd_quic_common.h"
#include "fd_quic_enum.h"
#include "fd_quic_pkt_meta.h"
#include "fd_quic_private.h"

ulong
fd_quic_conn_align( void ) {
  return alignof( fd_quic_conn_t );
}

ulong
fd_quic_conn_footprint( fd_quic_limits_t const * limits ) {
  (void)limits;
  return fd_ulong_align_up( sizeof( fd_quic_conn_t ), fd_quic_conn_align() );
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

  /* Initialize conn */

  fd_quic_conn_t * conn = (fd_quic_conn_t *)mem;
  fd_memset( conn, 0, sizeof(fd_quic_conn_t) );

  conn->quic     = quic;
  conn->state    = FD_QUIC_CONN_STATE_INVALID;

  quic->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_INVALID ]++;

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
