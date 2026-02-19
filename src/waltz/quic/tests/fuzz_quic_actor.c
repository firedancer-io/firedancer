#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_quic_test_helpers.h"
#include "../../tls/test_tls_helper.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../fd_quic_private.h"

#include <assert.h>
#include <stdlib.h>

#define FUZZ_MAX_OPS         (128UL)
#define FUZZ_MAX_PAYLOAD_SZ  (1024UL)
#define FUZZ_HS_ITERS        (80UL)
#define FUZZ_STEP_NS_MIN     (1000L)
#define FUZZ_STEP_NS_MAX     (5000000L)

#define FUZZ_ACTOR_CLIENT ((uchar)0u)
#define FUZZ_ACTOR_SERVER ((uchar)1u)

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         data_off;
} fuzz_cursor_t;

typedef struct {
  fd_quic_conn_t *   conn;
  fd_quic_stream_t * last_stream;
  ulong              reply_budget;
  ulong              rx_events;
} fuzz_peer_state_t;

typedef enum {
  FUZZ_OP_SERVICE = 0,
  FUZZ_OP_SEND,
  FUZZ_OP_FIN,
  FUZZ_OP_CLOSE,
  FUZZ_OP_RECONNECT,
  FUZZ_OP_LIMITS,
  FUZZ_OP_PING,
  FUZZ_OP_RAW_UDP,
  FUZZ_OP_VALIDATE,
} fuzz_op_kind_t;

typedef enum {
  FUZZ_PHASE_BOOT = 0,
  FUZZ_PHASE_ACTIVE,
  FUZZ_PHASE_RECOVERY,
} fuzz_phase_t;

typedef struct {
  long step_ns;
  uint rounds;
} fuzz_op_service_t;

typedef struct {
  uchar  actor;
  uchar  stream_mode;
  uchar  fin_mode;
  uchar  payload_mode;
  uchar  burst;
  uchar  service_rounds;
  ushort payload_base;
  ushort payload_span;
  ulong  seed;
} fuzz_op_send_t;

typedef struct {
  uchar actor;
} fuzz_op_actor_t;

typedef struct {
  uchar actor;
  uint  app_err;
} fuzz_op_close_t;

typedef struct {
  ulong seed;
} fuzz_op_reconnect_t;

typedef struct {
  uchar actor;
  uchar style;
  ulong max_data_inc;
  ulong stream_data;
  ulong stream_window;
} fuzz_op_limits_t;

typedef struct {
  uchar  actor;
  ushort payload_sz;
  ushort sport;
  ushort dport;
  uchar  tos;
  uchar  ttl;
  uchar  mutate_mode;
  ulong  seed;
} fuzz_op_raw_udp_t;

typedef struct {
  fuzz_op_kind_t kind;
  union {
    fuzz_op_service_t   service;
    fuzz_op_send_t      send;
    fuzz_op_actor_t     actor;
    fuzz_op_close_t     close;
    fuzz_op_reconnect_t reconnect;
    fuzz_op_limits_t    limits;
    fuzz_op_raw_udp_t   raw_udp;
  } u;
} fuzz_op_t;

typedef struct {
  fuzz_op_t ops[ FUZZ_MAX_OPS ];
  ulong     op_cnt;
} fuzz_program_t;

static fd_quic_limits_t const g_limits = {
  .conn_cnt           = 8UL,
  .handshake_cnt      = 8UL,
  .conn_id_cnt        = 8UL,
  .stream_id_cnt      = 128UL,
  .inflight_frame_cnt = 4096UL,
  .stream_pool_cnt    = 2048UL,
  .tx_buf_sz          = 1UL<<15UL,
};

static fd_quic_t * g_client_quic = NULL;
static fd_quic_t * g_server_quic = NULL;

static fuzz_peer_state_t g_client_state;
static fuzz_peer_state_t g_server_state;

static int g_client_hs_complete = 0;
static int g_server_hs_complete = 0;

static inline uchar
fuzz_fallback_u8( fuzz_cursor_t const * cur ) {
  ulong h = fd_ulong_hash( cur->data_off ^ (cur->data_sz<<1) ^ 0x9e3779b97f4a7c15UL );
  return (uchar)h;
}

static inline uchar
fuzz_u8( fuzz_cursor_t * cur ) {
  if( FD_LIKELY( cur->data_off < cur->data_sz ) ) {
    return cur->data[ cur->data_off++ ];
  }
  cur->data_off++;
  return fuzz_fallback_u8( cur );
}

static inline ushort
fuzz_u16( fuzz_cursor_t * cur ) {
  ushort v = (ushort)fuzz_u8( cur );
  v |= (ushort)( (ushort)fuzz_u8( cur ) << 8u );
  return v;
}

static inline uint
fuzz_u32( fuzz_cursor_t * cur ) {
  uint v = (uint)fuzz_u16( cur );
  v |= (uint)( (uint)fuzz_u16( cur ) << 16u );
  return v;
}

static inline ulong
fuzz_u64( fuzz_cursor_t * cur ) {
  ulong lo = (ulong)fuzz_u32( cur );
  ulong hi = (ulong)fuzz_u32( cur );
  return lo | ( hi << 32u );
}

static inline ulong
fuzz_bounded( fuzz_cursor_t * cur,
              ulong           bound ) {
  return bound ? ( fuzz_u64( cur ) % bound ) : 0UL;
}

static void
fuzz_cb_conn_new( fd_quic_conn_t * conn,
                  void *           quic_ctx ) {
  fuzz_peer_state_t * state = (fuzz_peer_state_t *)quic_ctx;
  state->conn = conn;
  g_server_hs_complete = 1;
}

static void
fuzz_cb_conn_hs_complete( fd_quic_conn_t * conn,
                          void *           quic_ctx ) {
  fuzz_peer_state_t * state = (fuzz_peer_state_t *)quic_ctx;
  state->conn = conn;
  g_client_hs_complete = 1;
}

static void
fuzz_cb_conn_final( fd_quic_conn_t * conn,
                    void *           quic_ctx ) {
  fuzz_peer_state_t * state = (fuzz_peer_state_t *)quic_ctx;
  if( state->conn==conn ) state->conn = NULL;
  if( state->last_stream && state->last_stream->conn==conn ) state->last_stream = NULL;
}

static int
fuzz_cb_stream_rx( fd_quic_conn_t * conn,
                   ulong            stream_id,
                   ulong            offset,
                   uchar const *    data,
                   ulong            data_sz,
                   int              fin ) {
  (void)stream_id;

  fuzz_peer_state_t * state = (fuzz_peer_state_t *)conn->quic->cb.quic_ctx;
  state->rx_events++;

  if( FD_UNLIKELY( !state->reply_budget ) ) return FD_QUIC_SUCCESS;
  if( FD_UNLIKELY( conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) return FD_QUIC_SUCCESS;
  if( FD_UNLIKELY( !data_sz ) ) return FD_QUIC_SUCCESS;

  /* Replies are intentionally sparse and bounded to avoid self-amplifying loops. */
  if( FD_LIKELY( offset==0UL && ((data[0]^((uchar)fin))&3u)==0u ) ) {
    fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
    if( stream ) {
      ulong resp_sz = fd_ulong_min( data_sz, 128UL );
      int   resp_fin = ( fin | (int)(data[0]&1u) ) ? 1 : 0;
      int rc = fd_quic_stream_send( stream, data, resp_sz, resp_fin );
      if( rc==FD_QUIC_SUCCESS ) state->last_stream = stream;
    }
    state->reply_budget--;
  }

  return FD_QUIC_SUCCESS;
}

static void
fuzz_service_pair( long * now,
                   long   step_ns,
                   uint   rounds ) {
  long step = fd_long_if( step_ns > 0L, step_ns, 1L );
  for( uint j=0U; j<rounds; j++ ) {
    *now += step;
    fd_quic_service( g_client_quic, *now );
    fd_quic_service( g_server_quic, *now );
  }
  fd_quic_sync_clocks( g_client_quic, g_server_quic, *now );
}

static inline void
fuzz_grant_tx_limits( fd_quic_conn_t * conn,
                      ulong            max_data,
                      ulong            max_stream_data,
                      ulong            stream_window ) {
  if( FD_UNLIKELY( !conn ) ) return;

  conn->tx_max_data = fd_ulong_max( conn->tx_max_data, max_data );
  conn->tx_initial_max_stream_data_uni = fd_ulong_max( conn->tx_initial_max_stream_data_uni, max_stream_data );

  ulong sup = conn->tx_next_stream_id + stream_window;
  if( FD_LIKELY( sup > conn->tx_next_stream_id ) ) {
    conn->tx_sup_stream_id = fd_ulong_max( conn->tx_sup_stream_id, sup );
  }
}

static inline fuzz_peer_state_t *
fuzz_state_for_actor( uchar actor ) {
  return actor==FUZZ_ACTOR_SERVER ? &g_server_state : &g_client_state;
}

static inline fd_quic_t *
fuzz_quic_for_actor( uchar actor ) {
  return actor==FUZZ_ACTOR_SERVER ? g_server_quic : g_client_quic;
}

static inline int
fuzz_stream_is_valid( fd_quic_stream_t * stream,
                      fd_quic_conn_t *   conn ) {
  return !!( stream && stream->conn==conn && stream->stream_id!=FD_QUIC_STREAM_ID_UNUSED );
}

static inline int
fuzz_program_emit( fuzz_program_t *   prog,
                   fuzz_op_t const *  op ) {
  if( FD_UNLIKELY( prog->op_cnt>=FUZZ_MAX_OPS ) ) return 0;
  prog->ops[ prog->op_cnt++ ] = *op;
  return 1;
}

static inline fuzz_op_t
fuzz_make_actor_op( fuzz_op_kind_t kind,
                    uchar          actor ) {
  fuzz_op_t op = {
    .kind = kind,
    .u.actor = {
      .actor = actor
    }
  };
  return op;
}

static inline fuzz_op_t
fuzz_make_validate_op( void ) {
  fuzz_op_t op = {
    .kind = FUZZ_OP_VALIDATE,
    .u.actor = { .actor = FUZZ_ACTOR_CLIENT }
  };
  return op;
}

static fuzz_op_t
fuzz_make_service_op( fuzz_cursor_t * cur,
                      uchar           profile ) {
  long  base_step  = FUZZ_STEP_NS_MIN;
  ulong step_span  = 100000UL;
  uint  rounds_max = 2U;

  switch( (uint)profile & 3U ) {
    case 0U:
      base_step  = FUZZ_STEP_NS_MIN;
      step_span  = 250000UL;
      rounds_max = 3U;
      break;

    case 1U:
      base_step  = 100000L;
      step_span  = 4000000UL;
      rounds_max = 5U;
      break;

    case 2U:
      base_step  = 1000000L;
      step_span  = 9000000UL;
      rounds_max = 8U;
      break;

    case 3U:
    default:
      base_step  = 1000000L;
      step_span  = 200000000UL;
      rounds_max = 12U;
      break;
  }

  fuzz_op_t op = {
    .kind = FUZZ_OP_SERVICE,
    .u.service = {
      .step_ns = base_step + (long)fuzz_bounded( cur, step_span+1UL ),
      .rounds  = 1U + (uint)fuzz_bounded( cur, (ulong)rounds_max ),
    }
  };
  return op;
}

static fuzz_op_t
fuzz_make_send_op( fuzz_cursor_t * cur,
                   uchar           actor,
                   uchar           burst_bias ) {
  ulong max_payload = 32UL + fuzz_bounded( cur, FUZZ_MAX_PAYLOAD_SZ - 31UL );
  ulong payload_base = 1UL + fuzz_bounded( cur, fd_ulong_min( max_payload, 160UL ) );
  ulong payload_span = 1UL + fuzz_bounded( cur, fd_ulong_max( max_payload-payload_base+1UL, 1UL ) );

  fuzz_op_t op = {
    .kind = FUZZ_OP_SEND,
    .u.send = {
      .actor          = actor,
      .stream_mode    = (uchar)fuzz_bounded( cur, 4UL ),
      .fin_mode       = (uchar)fuzz_bounded( cur, 4UL ),
      .payload_mode   = (uchar)fuzz_bounded( cur, 4UL ),
      .burst          = (uchar)( 1U + (uint)fuzz_bounded( cur, burst_bias ? 4UL : 2UL ) ),
      .service_rounds = (uchar)fuzz_bounded( cur, 3UL ),
      .payload_base   = (ushort)payload_base,
      .payload_span   = (ushort)payload_span,
      .seed           = fuzz_u64( cur ),
    }
  };

  return op;
}

static fuzz_op_t
fuzz_make_close_op( fuzz_cursor_t * cur,
                    uchar           actor ) {
  fuzz_op_t op = {
    .kind = FUZZ_OP_CLOSE,
    .u.close = {
      .actor   = actor,
      .app_err = fuzz_u32( cur ),
    }
  };
  return op;
}

static fuzz_op_t
fuzz_make_reconnect_op( fuzz_cursor_t * cur ) {
  fuzz_op_t op = {
    .kind = FUZZ_OP_RECONNECT,
    .u.reconnect = {
      .seed = fuzz_u64( cur )
    }
  };
  return op;
}

static fuzz_op_t
fuzz_make_limits_op( fuzz_cursor_t * cur,
                     uchar           actor ) {
  fuzz_op_t op = {
    .kind = FUZZ_OP_LIMITS,
    .u.limits = {
      .actor         = actor,
      .style         = (uchar)fuzz_bounded( cur, 4UL ),
      .max_data_inc  = (1UL<<12UL) + fuzz_bounded( cur, 1UL<<18UL ),
      .stream_data   = 256UL + fuzz_bounded( cur, 1UL<<16UL ),
      .stream_window = 4UL * ( 1UL + fuzz_bounded( cur, 64UL ) ),
    }
  };
  return op;
}

static fuzz_op_t
fuzz_make_raw_udp_op( fuzz_cursor_t * cur,
                      uchar           actor ) {
  ulong max_payload = FD_QUIC_MTU - sizeof(fd_ip4_hdr_t) - sizeof(fd_udp_hdr_t);

  fuzz_op_t op = {
    .kind = FUZZ_OP_RAW_UDP,
    .u.raw_udp = {
      .actor       = actor,
      .payload_sz  = (ushort)fuzz_bounded( cur, max_payload+1UL ),
      .sport       = (ushort)( 9000U + (ushort)fuzz_bounded( cur, 4096UL ) ),
      .dport       = (ushort)( 9000U + (ushort)fuzz_bounded( cur, 4096UL ) ),
      .tos         = fuzz_u8( cur ),
      .ttl         = (uchar)( 1u + (fuzz_u8( cur ) % 64u) ),
      .mutate_mode = (uchar)fuzz_bounded( cur, 4UL ),
      .seed        = fuzz_u64( cur ),
    }
  };
  return op;
}

static void
fuzz_emit_flow_block( fuzz_program_t * prog,
                      fuzz_cursor_t *  cur,
                      uchar            actor ) {
  fuzz_op_t op = fuzz_make_send_op( cur, actor, 1u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    op = fuzz_make_actor_op( FUZZ_OP_FIN, actor );
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  op = fuzz_make_service_op( cur, 1u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    uchar other = (uchar)( actor ^ 1u );
    op = fuzz_make_send_op( cur, other, 0u );
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  if( fuzz_u8( cur ) & 1u ) {
    op = fuzz_make_actor_op( FUZZ_OP_PING, actor );
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  op = fuzz_make_service_op( cur, 0u );
  (void)fuzz_program_emit( prog, &op );
}

static void
fuzz_emit_control_block( fuzz_program_t * prog,
                         fuzz_cursor_t *  cur,
                         uchar            actor ) {
  fuzz_op_t op = fuzz_make_limits_op( cur, actor );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    uchar other = (uchar)( actor ^ 1u );
    op = fuzz_make_limits_op( cur, other );
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  op = fuzz_make_actor_op( FUZZ_OP_PING, actor );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_service_op( cur, 1u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    op = fuzz_make_validate_op();
    (void)fuzz_program_emit( prog, &op );
  }
}

static void
fuzz_emit_noise_block( fuzz_program_t * prog,
                       fuzz_cursor_t *  cur,
                       uchar            actor ) {
  fuzz_op_t op = fuzz_make_raw_udp_op( cur, actor );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    uchar other = (uchar)( actor ^ 1u );
    op = fuzz_make_raw_udp_op( cur, other );
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  op = fuzz_make_service_op( cur, 0u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    op = fuzz_make_send_op( cur, actor, 0u );
    (void)fuzz_program_emit( prog, &op );
  }
}

static void
fuzz_emit_lifecycle_block( fuzz_program_t * prog,
                           fuzz_cursor_t *  cur,
                           uchar            actor ) {
  fuzz_op_t op = fuzz_make_close_op( cur, actor );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_service_op( cur, 3u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_reconnect_op( cur );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_service_op( cur, 2u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_limits_op( cur, FUZZ_ACTOR_CLIENT );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_limits_op( cur, FUZZ_ACTOR_SERVER );
  (void)fuzz_program_emit( prog, &op );
}

static void
fuzz_emit_validate_block( fuzz_program_t * prog,
                          fuzz_cursor_t *  cur ) {
  fuzz_op_t op = fuzz_make_validate_op();
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  op = fuzz_make_service_op( cur, 0u );
  (void)fuzz_program_emit( prog, &op );
}

static void
fuzz_decode_program( fuzz_cursor_t *  cur,
                     fuzz_program_t * prog ) {
  prog->op_cnt = 0UL;

  fuzz_phase_t phase = FUZZ_PHASE_BOOT;
  ulong block_cnt = 12UL + fuzz_bounded( cur, 48UL );

  fuzz_op_t op = fuzz_make_service_op( cur, 0u );
  if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;

  if( fuzz_u8( cur ) & 1u ) {
    op = fuzz_make_validate_op();
    if( FD_UNLIKELY( !fuzz_program_emit( prog, &op ) ) ) return;
  }

  for( ulong block=0UL; block<block_cnt && prog->op_cnt<FUZZ_MAX_OPS; block++ ) {
    uchar production;

    switch( phase ) {
      case FUZZ_PHASE_BOOT:     production = (uchar)fuzz_bounded( cur, 3UL ); break;
      case FUZZ_PHASE_ACTIVE:   production = (uchar)fuzz_bounded( cur, 6UL ); break;
      case FUZZ_PHASE_RECOVERY: production = (uchar)fuzz_bounded( cur, 4UL ); break;
      default:                  production = 0u;                               break;
    }

    if( phase==FUZZ_PHASE_BOOT ) {
      switch( production ) {
        case 0u:  fuzz_emit_flow_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
        case 1u:  fuzz_emit_flow_block( prog, cur, FUZZ_ACTOR_SERVER ); break;
        default:  fuzz_emit_control_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
      }
      if( prog->op_cnt > 16UL ) phase = FUZZ_PHASE_ACTIVE;
      continue;
    }

    if( phase==FUZZ_PHASE_ACTIVE ) {
      switch( production ) {
        case 0u:  fuzz_emit_flow_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
        case 1u:  fuzz_emit_flow_block( prog, cur, FUZZ_ACTOR_SERVER ); break;
        case 2u:  fuzz_emit_control_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
        case 3u:  fuzz_emit_control_block( prog, cur, FUZZ_ACTOR_SERVER ); break;
        case 4u:  fuzz_emit_noise_block( prog, cur, (uchar)fuzz_bounded( cur, 2UL ) ); break;
        case 5u:
        default:
          fuzz_emit_lifecycle_block( prog, cur, (uchar)fuzz_bounded( cur, 2UL ) );
          phase = FUZZ_PHASE_RECOVERY;
          break;
      }
      continue;
    }

    switch( production ) {
      case 0u:  fuzz_emit_control_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
      case 1u:  fuzz_emit_flow_block( prog, cur, FUZZ_ACTOR_CLIENT ); break;
      case 2u:  fuzz_emit_noise_block( prog, cur, FUZZ_ACTOR_SERVER ); break;
      case 3u:
      default:
        fuzz_emit_validate_block( prog, cur );
        phase = FUZZ_PHASE_ACTIVE;
        break;
    }

    if( (block & 3UL)==3UL ) phase = FUZZ_PHASE_ACTIVE;
  }

  op = fuzz_make_service_op( cur, 2u );
  (void)fuzz_program_emit( prog, &op );

  op = fuzz_make_validate_op();
  (void)fuzz_program_emit( prog, &op );
}

static void
fuzz_fill_payload( uchar *               payload,
                   ulong                 payload_sz,
                   fuzz_op_send_t const * spec,
                   ulong                 burst_idx ) {
  ulong seed = fd_ulong_hash( spec->seed ^ (burst_idx*0x9e3779b97f4a7c15UL) ^ (ulong)spec->payload_mode );

  if( FD_UNLIKELY( !payload_sz ) ) return;

  switch( (uint)spec->payload_mode & 3U ) {
    case 0U:
      for( ulong i=0UL; i<payload_sz; i++ ) {
        seed = fd_ulong_hash( seed ^ (i+1UL) );
        payload[i] = (uchar)( seed >> (int)((i & 7UL) * 8UL) );
      }
      break;

    case 1U:
      payload[0] = (uchar)( 0x80u | ((uint)spec->actor<<5) | (uint)(burst_idx & 0x1fUL) );
      for( ulong i=1UL; i<payload_sz; i++ ) {
        payload[i] = (uchar)( (uchar)i + (uchar)(seed>>((int)(i & 7UL)*8)) );
      }
      break;

    case 2U:
      for( ulong i=0UL; i<payload_sz; i++ ) {
        if( FD_UNLIKELY( !(i & 3UL) ) ) seed = fd_ulong_hash( seed + i + 0x12345UL );
        payload[i] = (uchar)( ((seed>>((int)((i>>2UL)&7UL)*8)) & 0xffUL) ^ (0x30UL + (i & 0x1fUL)) );
      }
      break;

    case 3U:
    default: {
      ulong half = (payload_sz+1UL)>>1UL;
      for( ulong i=0UL; i<half; i++ ) {
        seed = fd_ulong_hash( seed + (i|1UL) );
        uchar v = (uchar)seed;
        payload[i] = v;
        payload[payload_sz-1UL-i] = (uchar)(v ^ 0x5au);
      }
      break;
    }
  }
}

static fd_quic_stream_t *
fuzz_select_stream( fuzz_peer_state_t * state,
                    fd_quic_conn_t *   conn,
                    uchar              stream_mode,
                    ulong              seed ) {
  fd_quic_stream_t * stream = state->last_stream;
  int valid = fuzz_stream_is_valid( stream, conn );

  switch( (uint)stream_mode & 3U ) {
    case 0U: return valid ? stream : fd_quic_conn_new_stream( conn );
    case 1U: return fd_quic_conn_new_stream( conn );
    case 2U: return valid ? stream : NULL;
    case 3U: return valid && (seed & 1UL) ? stream : fd_quic_conn_new_stream( conn );
    default: return NULL;
  }
}

static int
fuzz_compute_fin( fuzz_op_send_t const * spec,
                  ulong                  burst_idx ) {
  switch( (uint)spec->fin_mode & 3U ) {
    case 0U: return 0;
    case 1U: return burst_idx+1UL >= (ulong)spec->burst;
    case 2U: return !!(burst_idx & 1UL);
    case 3U: return 1;
    default: return 0;
  }
}

static void
fuzz_execute_send( fuzz_op_send_t const * spec,
                   long *                 now ) {
  fuzz_peer_state_t * state = fuzz_state_for_actor( spec->actor );
  fd_quic_conn_t * conn = state->conn;

  if( FD_UNLIKELY( !conn ) ) return;
  if( FD_UNLIKELY( conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) return;

  ulong burst = fd_ulong_max( (ulong)spec->burst, 1UL );
  ulong step_ns = 1000UL + (spec->seed % 4000000UL);

  for( ulong burst_idx=0UL; burst_idx<burst; burst_idx++ ) {
    fd_quic_stream_t * stream = fuzz_select_stream( state, conn, spec->stream_mode, spec->seed ^ burst_idx );
    if( FD_UNLIKELY( !stream ) ) continue;

    ulong payload_span = fd_ulong_max( (ulong)spec->payload_span, 1UL );
    ulong payload_sz = (ulong)spec->payload_base + ((spec->seed >> (int)((burst_idx & 7UL) * 8UL)) % payload_span);
    payload_sz = fd_ulong_max( payload_sz, 1UL );
    payload_sz = fd_ulong_min( payload_sz, FUZZ_MAX_PAYLOAD_SZ );

    uchar payload[ FUZZ_MAX_PAYLOAD_SZ ];
    fuzz_fill_payload( payload, payload_sz, spec, burst_idx );

    int fin = fuzz_compute_fin( spec, burst_idx );

    if( FD_LIKELY( payload_sz ) && ((spec->seed ^ burst_idx) & 1UL) ) {
      /* Make it easier to trigger bounded application-level reply behavior. */
      payload[0] = (uchar)( (payload[0] & 0xfcu) | (uchar)fin );
    }

    int rc = fd_quic_stream_send( stream, payload, payload_sz, fin );
    if( FD_UNLIKELY( rc==FD_QUIC_SEND_ERR_FLOW && payload_sz>1UL ) ) {
      rc = fd_quic_stream_send( stream, payload, fd_ulong_max( payload_sz>>1UL, 1UL ), fin );
    }

    if( FD_LIKELY( rc==FD_QUIC_SUCCESS ) ) state->last_stream = stream;

    if( spec->service_rounds ) {
      fuzz_service_pair( now, (long)step_ns, (uint)spec->service_rounds );
    }

    if( FD_UNLIKELY( fin ) ) break;
  }
}

static void
fuzz_adjust_limits( fd_quic_conn_t *         conn,
                    fuzz_op_limits_t const * spec ) {
  if( FD_UNLIKELY( !conn ) ) return;

  ulong max_data = conn->tx_tot_data + spec->max_data_inc;
  ulong stream_data = spec->stream_data;
  ulong sup = conn->tx_next_stream_id + spec->stream_window;
  int has_sup = (sup > conn->tx_next_stream_id);

  switch( (uint)spec->style & 3U ) {
    case 0U:
      conn->tx_max_data = fd_ulong_max( conn->tx_max_data, max_data );
      conn->tx_initial_max_stream_data_uni = fd_ulong_max( conn->tx_initial_max_stream_data_uni, stream_data );
      if( FD_LIKELY( has_sup ) ) conn->tx_sup_stream_id = fd_ulong_max( conn->tx_sup_stream_id, sup );
      break;

    case 1U:
      conn->tx_max_data = fd_ulong_max( conn->tx_tot_data, max_data );
      conn->tx_initial_max_stream_data_uni = stream_data;
      if( FD_LIKELY( has_sup ) ) conn->tx_sup_stream_id = sup;
      break;

    case 2U:
      conn->tx_max_data = max_data;
      conn->tx_initial_max_stream_data_uni = fd_ulong_max( stream_data, 512UL );
      if( FD_LIKELY( has_sup ) ) conn->tx_sup_stream_id = fd_ulong_max( conn->tx_sup_stream_id, sup + 4UL );
      break;

    case 3U:
    default:
      conn->tx_max_data = fd_ulong_max( conn->tx_max_data, conn->tx_tot_data + (spec->max_data_inc>>1UL) );
      conn->tx_initial_max_stream_data_uni = fd_ulong_max( conn->tx_initial_max_stream_data_uni, stream_data>>1UL );
      if( FD_LIKELY( has_sup ) ) conn->tx_sup_stream_id = fd_ulong_max( conn->tx_sup_stream_id, sup );
      break;
  }
}

static void
fuzz_fill_raw_payload( uchar * out,
                       ulong   out_sz,
                       ulong   seed,
                       uchar   mutate_mode ) {
  ulong x = fd_ulong_hash( seed ^ ((ulong)mutate_mode<<32) );
  for( ulong i=0UL; i<out_sz; i++ ) {
    x = fd_ulong_hash( x + i + 0x9e37UL );
    out[i] = (uchar)( x >> (int)((i & 7UL) * 8UL) );
  }
}

static void
fuzz_send_raw_udp( fd_quic_t *               quic,
                   fd_quic_conn_t *          conn,
                   fuzz_op_raw_udp_t const * spec,
                   long                      now ) {
  uchar pkt[ FD_QUIC_MTU ];
  uchar * cur_ptr = pkt;
  uchar * end_ptr = pkt + sizeof(pkt);

  ulong max_payload = sizeof(pkt) - sizeof(fd_ip4_hdr_t) - sizeof(fd_udp_hdr_t);
  ulong payload_sz  = fd_ulong_min( (ulong)spec->payload_sz, max_payload );

  uint   saddr = conn ? conn->peer[0].ip_addr : FD_IP4_ADDR( 127, 1, 0, 1 );
  uint   daddr = conn ? conn->host.ip_addr    : FD_IP4_ADDR( 127, 1, 0, 2 );
  ushort sport = conn ? conn->peer[0].udp_port : spec->sport;
  ushort dport = conn ? conn->host.udp_port    : spec->dport;

  fd_ip4_hdr_t ip4 = {
    .verihl      = FD_IP4_VERIHL(4,5),
    .tos         = spec->tos,
    .net_tot_len = (ushort)( sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t) + payload_sz ),
    .net_id      = (ushort)spec->seed,
    .net_frag_off= 0x4000u,
    .ttl         = spec->ttl,
    .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
    .check       = 0,
    .saddr       = saddr,
    .daddr       = daddr,
  };

  fd_udp_hdr_t udp = {
    .net_sport = sport,
    .net_dport = dport,
    .net_len   = (ushort)( sizeof(fd_udp_hdr_t) + payload_sz ),
    .check     = 0,
  };

  switch( (uint)spec->mutate_mode & 3U ) {
    case 0U:
      break;

    case 1U:
      ip4.ttl = (uchar)( 1u + ((uchar)spec->seed & 31u) );
      break;

    case 2U:
      udp.net_len = (ushort)( udp.net_len + (ushort)(1u + (ushort)(spec->seed & 7UL)) );
      break;

    case 3U:
    default:
      ip4.tos ^= (uchar)( 1u << (uint)(spec->seed & 3UL) );
      ip4.net_frag_off = (ushort)( ip4.net_frag_off ^ (ushort)(spec->seed & 0x1fffUL) );
      break;
  }

  ulong rc = fd_quic_encode_ip4( cur_ptr, (ulong)(end_ptr-cur_ptr), &ip4 );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return;
  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)fd_type_pun( cur_ptr );
  ip4_hdr->check = (ushort)fd_ip4_hdr_check_fast( ip4_hdr );
  cur_ptr += rc;

  rc = fd_quic_encode_udp( cur_ptr, (ulong)(end_ptr-cur_ptr), &udp );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return;
  cur_ptr += rc;

  if( FD_UNLIKELY( cur_ptr + payload_sz > end_ptr ) ) return;
  fuzz_fill_raw_payload( cur_ptr, payload_sz, spec->seed, spec->mutate_mode );

  if( FD_LIKELY( payload_sz ) && ((spec->mutate_mode & 1u)!=0u) ) {
    ulong i = spec->seed % payload_sz;
    cur_ptr[i] ^= (uchar)(0xa5u ^ (uchar)(spec->seed>>8));
  }

  fd_quic_process_packet( quic, pkt, sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)+payload_sz, now );
}

static void
fuzz_execute_op( fuzz_op_t const * op,
                 long *            now ) {
  switch( op->kind ) {
    case FUZZ_OP_SERVICE:
      fuzz_service_pair( now, op->u.service.step_ns, op->u.service.rounds );
      break;

    case FUZZ_OP_SEND:
      fuzz_execute_send( &op->u.send, now );
      break;

    case FUZZ_OP_FIN: {
      fuzz_peer_state_t * state = fuzz_state_for_actor( op->u.actor.actor );
      if( fuzz_stream_is_valid( state->last_stream, state->conn ) ) {
        fd_quic_stream_fin( state->last_stream );
      }
      break;
    }

    case FUZZ_OP_CLOSE: {
      fuzz_peer_state_t * state = fuzz_state_for_actor( op->u.close.actor );
      if( state->conn ) fd_quic_conn_close( state->conn, op->u.close.app_err );
      break;
    }

    case FUZZ_OP_RECONNECT:
      if( !g_client_state.conn ||
          g_client_state.conn->state==FD_QUIC_CONN_STATE_DEAD ||
          g_client_state.conn->state==FD_QUIC_CONN_STATE_INVALID ) {
        g_client_state.last_stream = NULL;
        g_server_state.last_stream = NULL;
        g_client_state.conn = fd_quic_connect( g_client_quic, 0U, 0, 0U, 0, *now );

        long step_ns = (long)( 1000000UL + (op->u.reconnect.seed % 9000000UL) );
        uint rounds  = (uint)( 2U + (uint)(op->u.reconnect.seed & 3UL) );
        fuzz_service_pair( now, step_ns, rounds );

        fuzz_grant_tx_limits( g_client_state.conn, 1UL<<20UL, 1UL<<15UL, 256UL );
        fuzz_grant_tx_limits( g_server_state.conn, 1UL<<20UL, 1UL<<15UL, 256UL );
      }
      break;

    case FUZZ_OP_LIMITS: {
      fuzz_peer_state_t * state = fuzz_state_for_actor( op->u.limits.actor );
      fuzz_adjust_limits( state->conn, &op->u.limits );
      break;
    }

    case FUZZ_OP_PING: {
      fuzz_peer_state_t * state = fuzz_state_for_actor( op->u.actor.actor );
      if( state->conn ) {
        state->conn->flags |= FD_QUIC_CONN_FLAGS_PING;
        state->conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
      }
      break;
    }

    case FUZZ_OP_RAW_UDP: {
      fuzz_peer_state_t * state = fuzz_state_for_actor( op->u.raw_udp.actor );
      fd_quic_t * quic = fuzz_quic_for_actor( op->u.raw_udp.actor );
      fuzz_send_raw_udp( quic, state->conn, &op->u.raw_udp, *now );
      break;
    }

    case FUZZ_OP_VALIDATE:
      fd_quic_state_validate( g_client_quic );
      fd_quic_state_validate( g_server_quic );
      break;

    default:
      __builtin_unreachable();
      break;
  }
}

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  ulong footprint = fd_quic_footprint( &g_limits );
  assert( footprint );
  footprint = fd_ulong_align_up( footprint, fd_quic_align() );

  void * client_mem = aligned_alloc( fd_quic_align(), footprint );
  void * server_mem = aligned_alloc( fd_quic_align(), footprint );
  assert( client_mem );
  assert( server_mem );

  fd_quic_t * client_quic = fd_quic_join( fd_quic_new( client_mem, &g_limits ) );
  fd_quic_t * server_quic = fd_quic_join( fd_quic_new( server_mem, &g_limits ) );
  assert( client_quic );
  assert( server_quic );

  g_client_quic = client_quic;
  g_server_quic = server_quic;

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fuzz_cursor_t cur = {
    .data     = data,
    .data_sz  = size,
    .data_off = 0UL,
  };

  fd_rng_t _rng[1];
  ulong seed = size >= sizeof(ulong) ? FD_LOAD( ulong, data + size - sizeof(ulong) ) : 0UL;
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)seed, seed ) );

  g_client_state = (fuzz_peer_state_t){0};
  g_server_state = (fuzz_peer_state_t){0};
  g_client_hs_complete = 0;
  g_server_hs_complete = 0;

  fd_quic_config_anonymous( g_client_quic, FD_QUIC_ROLE_CLIENT );
  fd_quic_config_anonymous( g_server_quic, FD_QUIC_ROLE_SERVER );

  fd_tls_test_sign_ctx_t client_signer[1];
  fd_tls_test_sign_ctx_t server_signer[1];
  fd_tls_test_sign_ctx( client_signer, rng );
  fd_tls_test_sign_ctx( server_signer, rng );
  fd_quic_config_test_signer( g_client_quic, client_signer );
  fd_quic_config_test_signer( g_server_quic, server_signer );

  g_client_quic->cb.quic_ctx         = &g_client_state;
  g_client_quic->cb.conn_hs_complete = fuzz_cb_conn_hs_complete;
  g_client_quic->cb.conn_final       = fuzz_cb_conn_final;
  g_client_quic->cb.stream_rx        = fuzz_cb_stream_rx;

  g_server_quic->cb.quic_ctx         = &g_server_state;
  g_server_quic->cb.conn_new         = fuzz_cb_conn_new;
  g_server_quic->cb.conn_final       = fuzz_cb_conn_final;
  g_server_quic->cb.stream_rx        = fuzz_cb_stream_rx;

  g_client_quic->config.keep_alive = !!(fuzz_u8( &cur ) & 1u);
  g_server_quic->config.retry      = !!(fuzz_u8( &cur ) & 1u);

  g_client_quic->config.idle_timeout = (long)( 1e6 + (double)fuzz_bounded( &cur, 1500UL ) * 1e6 );
  g_server_quic->config.idle_timeout = (long)( 1e6 + (double)fuzz_bounded( &cur, 1500UL ) * 1e6 );

  g_client_quic->config.ack_delay = (long)( 1000L + (long)fuzz_bounded( &cur, (ulong)20e6 ) );
  g_server_quic->config.ack_delay = (long)( 1000L + (long)fuzz_bounded( &cur, (ulong)20e6 ) );

  g_client_quic->config.initial_rx_max_stream_data = 256UL + fuzz_bounded( &cur, 1UL<<15UL );
  g_server_quic->config.initial_rx_max_stream_data = 256UL + fuzz_bounded( &cur, 1UL<<15UL );

  fd_aio_t const * client_rx = fd_quic_get_aio_net_rx( g_client_quic );
  fd_aio_t const * server_rx = fd_quic_get_aio_net_rx( g_server_quic );

  fd_quic_set_aio_net_tx( g_client_quic, server_rx );
  fd_quic_set_aio_net_tx( g_server_quic, client_rx );

  if( FD_UNLIKELY( !fd_quic_init( g_server_quic ) ) ) goto cleanup_rng;
  if( FD_UNLIKELY( !fd_quic_init( g_client_quic ) ) ) {
    fd_quic_fini( g_server_quic );
    goto cleanup_rng;
  }

  long now = 1000000L;
  fd_quic_sync_clocks( g_client_quic, g_server_quic, now );

  g_client_state.conn = fd_quic_connect( g_client_quic, 0U, 0, 0U, 0, now );

  for( ulong j=0UL; j<FUZZ_HS_ITERS; j++ ) {
    if( g_client_hs_complete & g_server_hs_complete ) break;
    fuzz_service_pair( &now, 1000000L, 1U );
  }

  fuzz_grant_tx_limits( g_client_state.conn, 1UL<<20UL, 1UL<<15UL, 256UL );
  fuzz_grant_tx_limits( g_server_state.conn, 1UL<<20UL, 1UL<<15UL, 256UL );

  g_client_state.reply_budget = fuzz_bounded( &cur, 32UL );
  g_server_state.reply_budget = fuzz_bounded( &cur, 32UL );

  fuzz_program_t prog[1];
  fuzz_decode_program( &cur, prog );

  for( ulong op_idx=0UL; op_idx<prog->op_cnt; op_idx++ ) {
    FD_FUZZ_MUST_BE_COVERED;
    fuzz_execute_op( &prog->ops[ op_idx ], &now );
  }

  fuzz_service_pair( &now, 1000000L, 4U );
  fd_quic_state_validate( g_client_quic );
  fd_quic_state_validate( g_server_quic );

  fd_quic_fini( g_client_quic );
  fd_quic_fini( g_server_quic );

cleanup_rng:
  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
