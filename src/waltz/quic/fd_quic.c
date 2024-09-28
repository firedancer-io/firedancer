#include "fd_quic.h"
#include "fd_quic_ack_tx.h"
#include "fd_quic_common.h"
#include "fd_quic_conn_id.h"
#include "fd_quic_enum.h"
#include "fd_quic_pkt_meta.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_proto.h"
#include "fd_quic_retry.h"

#include "fd_quic_tx_streams.h"
#include "templ/fd_quic_frame_handler_decl.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"
#include "templ/fd_quic_frame_types_templ.h"

#include "crypto/fd_quic_crypto_suites.h"
#include "templ/fd_quic_transport_params.h"
#include "templ/fd_quic_parse_util.h"
#include "tls/fd_quic_tls.h"

#include "../../ballet/txn/fd_txn.h" /* FD_TXN_MTU */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>   /* for keylog open(2)  */
#include <unistd.h>  /* for keylog close(2) */

#include "../../ballet/x509/fd_x509_mock.h"
#include "../../ballet/hex/fd_hex.h"

/* Declare priority queue for time based processing */
#define PRQ_NAME      service_queue
#define PRQ_T         fd_quic_event_t
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"


/* FD_QUIC_PING_ENABLE
 *
 * This compile time option specifies whether the server should use
 * QUIC PING frames to keep connections alive
 *
 * Set to 1 to keep connections alive
 * Set to 0 to allow connections to close on idle */
# define FD_QUIC_PING_ENABLE 0

/* FD_QUIC_MAX_STREAMS_ALWAYS  */
/* Defines whether a MAX_STREAMS frame is sent even if it was just */
/* sent */
/* They take very little space, and a dropped MAX_STREAMS frame can */
/* be very consequential */
/* Even when set, QUIC won't send this frame if the client has ackd */
/* the most recent value */
# define FD_QUIC_MAX_STREAMS_ALWAYS 1



/* Construction API ***************************************************/

FD_QUIC_API FD_FN_CONST ulong
fd_quic_align( void ) {
  return FD_QUIC_ALIGN;
}

/* fd_quic_layout_t describes the memory layout of an fd_quic_t */
struct fd_quic_layout {
  ulong conns_off;       /* offset of connection mem region  */
  ulong conn_map_off;    /* offset of conn map mem region    */
  ulong event_queue_off; /* offset of event queue mem region */
  int   lg_slot_cnt;     /* see conn_map_new                 */
  ulong tls_off;         /* offset of fd_quic_tls_t          */
  ulong tx_streams_off;  /* offset of fd_quic_tx_streams_t   */
  ulong acks_off;        /* offset of fd_quic_ack_t[]        */
  ulong pkt_meta_off;    /* offset of fd_quic_pkt_meta_t[]   */
};
typedef struct fd_quic_layout fd_quic_layout_t;

/* fd_quic_footprint_ext returns footprint of QUIC memory region given
   limits. Also writes byte offsets to given layout struct. */
static ulong
fd_quic_footprint_ext( fd_quic_limits_t const * limits,
                       fd_quic_layout_t *       layout ) {

  if( FD_UNLIKELY( !limits ) ) return 0UL;

  ulong  conn_cnt         = limits->conn_cnt;
  ulong  conn_id_cnt      = limits->conn_id_cnt;
  ulong  handshake_cnt    = limits->handshake_cnt;
  ulong  inflight_pkt_cnt = limits->inflight_pkt_cnt;
  ulong  tx_stream_cnt    = limits->tx_stream_cnt;

  if( FD_UNLIKELY( conn_cnt        ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( handshake_cnt   ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( inflight_pkt_cnt==0UL ) ) return 0UL;

  if( FD_UNLIKELY( conn_id_cnt < FD_QUIC_MIN_CONN_ID_CNT ))
    return 0UL;

  ulong offs  = 0;

  /* allocate space for fd_quic_t */
  offs += sizeof(fd_quic_t);

  /* allocate space for state */
  offs  = fd_ulong_align_up( offs, alignof(fd_quic_state_t) );
  offs += sizeof(fd_quic_state_t);

  /* allocate space for connections */
  offs                 = fd_ulong_align_up( offs, fd_quic_conn_pool_align() );
  layout->conns_off    = offs;
  offs                += fd_quic_conn_pool_footprint( conn_cnt );

  /* allocate space for conn IDs */
  offs                     = fd_ulong_align_up( offs, fd_quic_conn_map_align() );
  layout->conn_map_off     = offs;
  ulong slot_cnt_bound     = (ulong)( FD_QUIC_DEFAULT_SPARSITY * (double)conn_cnt * (double)conn_id_cnt );
  int     lg_slot_cnt      = fd_ulong_find_msb( slot_cnt_bound - 1 ) + 1;
  layout->lg_slot_cnt      = lg_slot_cnt;
  ulong conn_map_footprint = fd_quic_conn_map_footprint( lg_slot_cnt );
  if( FD_UNLIKELY( !conn_map_footprint ) ) { FD_LOG_WARNING(( "invalid fd_quic_conn_map_footprint" )); return 0UL; }
  offs                    += conn_map_footprint;

  /* allocate space for events priority queue */
  offs                        = fd_ulong_align_up( offs, service_queue_align() );
  layout->event_queue_off     = offs;
  ulong event_queue_footprint = service_queue_footprint( conn_cnt + 1 );
  if( FD_UNLIKELY( !event_queue_footprint ) ) { FD_LOG_WARNING(( "invalid service_queue_footprint" )); return 0UL; }
  offs                       += event_queue_footprint;

  /* allocate space for fd_quic_tls_t */
  offs                 = fd_ulong_align_up( offs, fd_quic_tls_align() );
  layout->tls_off      = offs;
  ulong tls_footprint  = fd_quic_tls_footprint( handshake_cnt );
  if( FD_UNLIKELY( !tls_footprint ) ) { FD_LOG_WARNING(( "invalid fd_quic_tls_footprint" )); return 0UL; }
  offs                += tls_footprint;

  /* allocate space for fd_quic_tx_stream_pool_t */
  offs                   = fd_ulong_align_up( offs, fd_quic_tx_stream_pool_align() );
  layout->tx_streams_off = offs;
  ulong tx_footprint     = fd_quic_tx_stream_pool_footprint( tx_stream_cnt );
  if( FD_UNLIKELY( !tx_footprint ) ) { FD_LOG_WARNING(( "invalid fd_quic_tx_stream_pool_footprint" )); return 0UL; }
  offs                  += tx_footprint;

  /* allocate space for fd_quic_ack_t */
  offs                 = fd_ulong_align_up( offs, alignof(fd_quic_ack_t) );
  layout->acks_off     = offs;
  ulong acks_footprint = inflight_pkt_cnt * sizeof(fd_quic_ack_t);
  offs                += acks_footprint;

  /* allocate space for fd_quic_pkt_meta_t */
  offs                     = fd_ulong_align_up( offs, alignof(fd_quic_pkt_meta_t) );
  layout->pkt_meta_off     = offs;
  ulong pkt_meta_footprint = inflight_pkt_cnt * sizeof(fd_quic_pkt_meta_t);
  offs                    += pkt_meta_footprint;

  return offs;
}

FD_QUIC_API FD_FN_PURE ulong
fd_quic_footprint( fd_quic_limits_t const * limits ) {
  fd_quic_layout_t layout;
  return fd_quic_footprint_ext( limits, &layout );
}

FD_QUIC_API void *
fd_quic_new( void * mem,
             fd_quic_limits_t const * limits ) {

  /* Argument checks */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong align = fd_quic_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !limits ) ) {
    FD_LOG_WARNING(( "NULL limits" ));
    return NULL;
  }

  if( FD_UNLIKELY( ( limits->conn_cnt        ==0UL )
                 | ( limits->handshake_cnt   ==0UL )
                 | ( limits->inflight_pkt_cnt==0UL ) ) ) {
    FD_LOG_WARNING(( "invalid limits" ));
    return NULL;
  }

  ulong footprint = fd_quic_footprint( limits );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  fd_quic_t * quic  = (fd_quic_t *)mem;

  /* Clear fd_quic_t memory region */
  fd_memset( quic, 0, footprint );

  /* Set limits */
  memcpy( &quic->limits, limits, sizeof( fd_quic_limits_t ) );

  FD_COMPILER_MFENCE();
  quic->magic = FD_QUIC_MAGIC;
  FD_COMPILER_MFENCE();

  return quic;
}

FD_QUIC_API fd_quic_limits_t *
fd_quic_limits_from_env( int  *   pargc,
                         char *** pargv,
                         fd_quic_limits_t * limits ) {

  if( FD_UNLIKELY( !limits ) ) return NULL;

  limits->conn_cnt         = fd_env_strip_cmdline_uint( pargc, pargv, "--quic-conns",         "QUIC_CONN_CNT",           512UL );
  limits->conn_id_cnt      = fd_env_strip_cmdline_uint( pargc, pargv, "--quic-conn-ids",      "QUIC_CONN_ID_CNT",         16UL );
  limits->tx_stream_cnt    = fd_env_strip_cmdline_uint( pargc, pargv, "--quic-streams",       "QUIC_STREAM_CNT",       16384UL );
  limits->handshake_cnt    = fd_env_strip_cmdline_uint( pargc, pargv, "--quic-handshakes",    "QUIC_HANDSHAKE_CNT",      512UL );
  limits->inflight_pkt_cnt = fd_env_strip_cmdline_uint( pargc, pargv, "--quic-inflight-pkts", "QUIC_MAX_INFLIGHT_PKTS", 2500UL );

  return limits;
}

FD_QUIC_API fd_quic_config_t *
fd_quic_config_from_env( int  *             pargc,
                         char ***           pargv,
                         fd_quic_config_t * cfg ) {

  if( FD_UNLIKELY( !cfg ) ) return NULL;

  char const * keylog_file     = fd_env_strip_cmdline_cstr ( pargc, pargv, NULL,             "SSLKEYLOGFILE", NULL  );
  ulong        idle_timeout_ms = fd_env_strip_cmdline_ulong( pargc, pargv, "--idle-timeout", NULL,            100UL );

  if( keylog_file ) {
    strncpy( cfg->keylog_file, keylog_file, FD_QUIC_PATH_LEN );
  } else {
    cfg->keylog_file[0]='\0';
  }

  cfg->idle_timeout = idle_timeout_ms * (ulong)1e6;

  cfg->net.ephem_udp_port.lo = 10000;
  cfg->net.ephem_udp_port.hi = 11000;

  return cfg;
}

FD_QUIC_API fd_aio_t const *
fd_quic_get_aio_net_rx( fd_quic_t * quic ) {
  fd_aio_new( &quic->aio_rx, quic, fd_quic_aio_cb_receive );
  return &quic->aio_rx;
}

FD_QUIC_API void
fd_quic_set_aio_net_tx( fd_quic_t *      quic,
                        fd_aio_t const * aio_tx ) {

  if( aio_tx ) {
    /* TODO unclear if memcpy violates fd_aio semantics (breaks downcasting) */
    memcpy( &quic->aio_tx, aio_tx, sizeof(fd_aio_t) );
  } else {
    memset( &quic->aio_tx, 0,      sizeof(fd_aio_t) );
  }
}

FD_QUIC_API fd_quic_t *
fd_quic_join( void * shquic ) {

  if( FD_UNLIKELY( !shquic ) ) {
    FD_LOG_WARNING(( "null shquic" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shquic, FD_QUIC_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned quic" ));
    return NULL;
  }

  fd_quic_t * quic = (fd_quic_t *)shquic;
  if( FD_UNLIKELY( quic->magic != FD_QUIC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return quic;
}

FD_QUIC_API void *
fd_quic_leave( fd_quic_t * quic ) {
  return (void *)quic;
}

FD_QUIC_API fd_quic_t *
fd_quic_init( fd_quic_t * quic ) {

  fd_quic_limits_t const * limits = &quic->limits;
  fd_quic_config_t       * config = &quic->config;

  if( FD_UNLIKELY( !config->role           ) ) { FD_LOG_WARNING(( "cfg.role not set"      )); return NULL; }
  if( FD_UNLIKELY( !config->idle_timeout   ) ) { FD_LOG_WARNING(( "zero cfg.idle_timeout" )); return NULL; }
  if( FD_UNLIKELY( !config->ack_delay_mask ) ) { config->ack_delay_mask = 0xfffffff; /* 268ms */ }
  if( FD_UNLIKELY( !fd_ulong_is_pow2( config->ack_delay_mask+1UL ) ) ) { FD_LOG_WARNING(( "invalid cfg.ack_delay_mask" )); return NULL; }
  if( FD_UNLIKELY( !config->ack_threshold  ) ) { config->ack_threshold = 0x10000; /* 64KB */ }
  while( config->ack_delay_mask > config->idle_timeout/2 ) {
    config->ack_delay_mask >>= 1;
  }

  do {
    ulong x = 0U;
    for( ulong i=0UL; i<32UL; i++ ) x |= quic->config.identity_public_key[i];

    if( FD_UNLIKELY( !x ) ) {
      FD_LOG_WARNING(( "cfg.identity_public_key not set" ));
      return NULL;
    }
  } while(0);

  switch( config->role ) {
  case FD_QUIC_ROLE_SERVER:
    if( FD_UNLIKELY( !config->net.listen_udp_port ) ) { FD_LOG_WARNING(( "no cfg.net.listen_udp_port" )); return NULL; }
    break;
  case FD_QUIC_ROLE_CLIENT:
    if( FD_UNLIKELY( !config->net.ephem_udp_port.lo
                  || !config->net.ephem_udp_port.hi
                  || config->net.ephem_udp_port.lo > config->net.ephem_udp_port.hi ) ) {
      FD_LOG_WARNING(( "invalid cfg.net.ephem_udp_port" ));
      return NULL;
    }
    break;
  default:
    FD_LOG_WARNING(( "invalid cfg.role" ));
    return NULL;
  }

  /* Derive memory layout */

  fd_quic_layout_t layout = {0};
  fd_quic_footprint_ext( limits, &layout );

  /* Reset state */

  fd_quic_state_t * state = fd_quic_get_state( quic );
  memset( state, 0, sizeof(fd_quic_state_t) );

  /* State: initialize each connection, and add to free list */

  ulong conn_laddr = (ulong)quic + layout.conns_off;
  state->conns = fd_quic_conn_pool_join( fd_quic_conn_pool_new( (void *)conn_laddr, limits->conn_cnt ) );
  for( uint j=0U; j<limits->conn_cnt; j++ ) {
    state->conns[j].conn_idx = j;
  }

  /* State: Initialize conn ID map */

  ulong  conn_map_laddr = (ulong)quic + layout.conn_map_off;
  state->conn_map = fd_quic_conn_map_join( fd_quic_conn_map_new( (void *)conn_map_laddr, layout.lg_slot_cnt ) );
  if( FD_UNLIKELY( !state->conn_map ) ) {
    FD_LOG_WARNING(( "NULL conn_map" ));
    return NULL;
  }

  /* State: Initialize service queue */

  ulong  service_queue_laddr = (ulong)quic + layout.event_queue_off;
  void * v_service_queue = service_queue_new( (void *)service_queue_laddr, limits->conn_cnt+1U );
  state->service_queue = service_queue_join( v_service_queue );
  if( FD_UNLIKELY( !state->service_queue ) ) {
    FD_LOG_WARNING(( "NULL service_queue" ));
    return NULL;
  }

  /* State: Initialize outgoing streams */

  if( config->role == FD_QUIC_ROLE_CLIENT ) {
    ulong tx_stream_cnt    = limits->tx_stream_cnt;
    ulong tx_streams_laddr = (ulong)quic + layout.tx_streams_off;
    state->tx_streams = fd_quic_tx_stream_pool_join( fd_quic_tx_stream_pool_new( (void*)tx_streams_laddr, tx_stream_cnt, state->_rng ) );
  } else {
    state->tx_streams = NULL;
  }

  /* State: Initialize packet meta pool */

  ulong pkt_meta_laddr = (ulong)quic + layout.pkt_meta_off;
  state->pkt_meta_pool = (fd_quic_pkt_meta_t *)pkt_meta_laddr;
  fd_quic_pkt_meta_list_new( state->pkt_meta_free );
  for( ulong j=0UL; j<limits->inflight_pkt_cnt; j++ ) {
    fd_quic_pkt_meta_list_idx_push_tail( state->pkt_meta_free, j, state->pkt_meta_pool );
  }

  /* Check TX AIO */

  if( FD_UNLIKELY( !quic->aio_tx.send_func ) ) {
    FD_LOG_WARNING(( "NULL aio_tx" ));
    return NULL;
  }

  /* State: Initialize TLS */

  fd_quic_tls_cfg_t tls_cfg = {
    .max_concur_handshakes = limits->handshake_cnt,

    /* set up callbacks */
    .secret_cb             = fd_quic_tls_cb_secret,
    .handshake_complete_cb = fd_quic_tls_cb_handshake_complete,
    .peer_params_cb        = fd_quic_tls_cb_peer_params,

    .signer = {
      .ctx     = config->sign_ctx,
      .sign_fn = config->sign,
    },

    .cert_public_key       = quic->config.identity_public_key,
  };

  /* fetch ahead */
  fd_quic_metrics_t * metrics = &quic->metrics;

  ulong tls_laddr = (ulong)quic + layout.tls_off;
  state->tls = fd_quic_tls_new( (void *)tls_laddr, &tls_cfg );
  if( FD_UNLIKELY( !state->tls ) ) {
    metrics->hs_err_alloc_fail_cnt++;
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_tls_new failed" ) ) );
    return NULL;
  }
  metrics->hs_created_cnt++;

  /* generate a secure random number as seed for fd_rng */
  uint rng_seed = 0;
  int rng_seed_ok = !!fd_rng_secure( &rng_seed, sizeof(rng_seed) );
  if( FD_UNLIKELY( !rng_seed_ok ) ) {
    FD_LOG_ERR(( "fd_rng_secure failed" ));
  }
  fd_rng_new( state->_rng, rng_seed, 0UL );

  /* use rng to generate secret bytes for future RETRY token generation */
  int rng1_ok = !!fd_rng_secure( state->retry_secret, FD_QUIC_RETRY_SECRET_SZ );
  int rng2_ok = !!fd_rng_secure( state->retry_iv,     FD_QUIC_RETRY_IV_SZ     );
  if( FD_UNLIKELY( !rng1_ok || !rng2_ok ) ) {
    FD_LOG_ERR(( "fd_rng_secure failed" ));
    return NULL;
  }

  /* Initialize transport params */

  fd_quic_transport_params_t * tp = &state->transport_params;

  /* initial max streams is zero */
  /* we will send max_streams and max_data frames later to allow the peer to */
  /* send us data */
  ulong initial_max_stream_data = FD_TXN_MTU;

  memset( tp, 0, sizeof(fd_quic_transport_params_t) );
  ulong idle_timeout_ms = (config->idle_timeout + 1000000UL - 1UL) / 1000000UL;
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_idle_timeout,                    idle_timeout_ms          );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_udp_payload_size,                FD_QUIC_MAX_PAYLOAD_SZ   ); /* TODO */
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_data,                    0                        );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_stream_data_uni,         initial_max_stream_data  );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_streams_bidi,            0                        );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_streams_uni,             0                        );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, ack_delay_exponent,                  0                        );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_ack_delay,                       10                       );
  /*                         */tp->disable_active_migration_present =   1;
  FD_QUIC_TRANSPORT_PARAM_SET( tp, active_connection_id_limit,          FD_QUIC_MAX_CONN_ID_PER_CONN );

  /* Initialize next ephemeral udp port */
  state->next_ephem_udp_port = config->net.ephem_udp_port.lo;

  return quic;
}

/* fd_quic_enc_level_to_pn_space maps of encryption level in [0,4) to
   packet number space. */
static uint
fd_quic_enc_level_to_pn_space( uint enc_level ) {
  /* TODO improve this map */
  static uchar const el2pn_map[] = { 0, 2, 1, 2 };

  if( FD_UNLIKELY( enc_level >= 4U ) )
    FD_LOG_ERR(( "fd_quic_enc_level_to_pn_space called with invalid enc_level" ));

  return el2pn_map[ enc_level ];
}

/* This code is directly from rfc9000 A.3 */
static void
fd_quic_reconstruct_pkt_num( ulong * pkt_number,
                             ulong   pkt_number_sz,
                             ulong   exp_pkt_number ) {
  ulong truncated_pn = *pkt_number;
  ulong pn_nbits     = pkt_number_sz << 3u;
  ulong pn_win       = 1ul << pn_nbits;
  ulong pn_hwin      = pn_win >> 1ul;
  ulong pn_mask      = pn_win - 1ul;
  // The incoming packet number should be greater than
  // exp_pkt_number - pn_hwin and less than or equal to
  // exp_pkt_number + pn_hwin
  //
  // This means we cannot just strip the trailing bits from
  // exp_pkt_number and add the truncated_pn because that might
  // yield a value outside the window.
  //
  // The following code calculates a candidate value and
  // makes sure it's within the packet number window.
  // Note the extra checks to prevent overflow and underflow.
  ulong candidate_pn = ( exp_pkt_number & ~pn_mask ) | truncated_pn;
  if( candidate_pn + pn_hwin <= exp_pkt_number &&
      candidate_pn + pn_win  < ( 1ul << 62ul ) ) {
    *pkt_number = candidate_pn + pn_win;
    return;
  }

  if( candidate_pn >  exp_pkt_number + pn_hwin &&
      candidate_pn >= pn_win ) {
    *pkt_number = candidate_pn - pn_win;
    return;
  }

  *pkt_number = candidate_pn;
}

/* set a connection to aborted, and set a reason code */
void
fd_quic_conn_error( fd_quic_conn_t * conn,
                    uint             reason,
                    uint             error_line ) {
  if( FD_UNLIKELY( !conn || conn->state == FD_QUIC_CONN_STATE_DEAD ) ) return;
  FD_DEBUG( FD_LOG_DEBUG(( "Terminating conn=%p (reason=%u) at fd_quic.c(%u)", (void *)conn, reason, error_line )); )

  conn->state  = FD_QUIC_CONN_STATE_ABORT;
  conn->reason = reason;
  conn->int_reason = error_line;

  /* set connection to be serviced ASAP */
  fd_quic_reschedule_conn( conn, 0 );
}

/* returns the encoding level we should use for the next tx quic packet
   or all 1's if nothing to tx */
static uint
fd_quic_tx_enc_level( fd_quic_conn_t * conn,
                      int              acks ) {
  fd_quic_state_t *     state   = fd_quic_get_state( conn->quic );
  fd_quic_tx_stream_t * tx_pool = fd_quic_tx_stream_pool( state->tx_streams );

  uint enc_level = ~0u;

  uint  app_pn_space   = fd_quic_enc_level_to_pn_space( fd_quic_enc_level_appdata_id );
  ulong app_pkt_number = conn->pkt_number[app_pn_space];

  /* fd_quic_tx_enc_level( ... )
       check status - if closing, set based on handshake complete
       check for acks
       check for hs_data
         find lowest enc level
       if any, use lowest
       else
         if stream data, use 1-rtt
       else
         nothing to do */

  /* check status */
  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_DEAD:
      /* do not send on dead connection at all */
      return ~0u;

    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
      /* use handshake or app enc level depending on handshake complete */
      if( !(conn->flags & FD_QUIC_CONN_FLAGS_CLOSE_SENT ) ) {
        if( conn->handshake_complete ) {
          return fd_quic_enc_level_appdata_id;
        } else if( fd_uint_extract_bit( conn->keys_avail, fd_quic_enc_level_handshake_id ) ) {
          return fd_quic_enc_level_handshake_id;
        } else if( fd_uint_extract_bit( conn->keys_avail, fd_quic_enc_level_initial_id ) ) {
          return fd_quic_enc_level_initial_id;
        }
      }
      return ~0u;

      /* TODO consider this optimization... but we want to ack all handshakes, even if there is stream_data */
    case FD_QUIC_CONN_STATE_ACTIVE:
      if( FD_LIKELY( conn->hs_data_empty ) ) {
        /* optimization for case where we have stream data to send */

        /* find stream data to send */
        fd_quic_tx_stream_t * stream = fd_quic_tx_stream_dlist_ele_peek_head( conn->send_streams, tx_pool );
        if( !fd_quic_tx_stream_dlist_is_empty( conn->send_streams, tx_pool ) && stream->upd_pkt_number >= app_pkt_number ) {
          return fd_quic_enc_level_appdata_id;
        }
      }
  }

  /* pick enc_level of oldest ACK not yet sent */
  fd_quic_ack_gen_t *   ack_gen    = conn->ack_gen;
  fd_quic_ack_t const * oldest_ack = fd_quic_ack_queue_ele( ack_gen, ack_gen->tail );
  uint ack_enc_level = oldest_ack->enc_level; /* speculative load (might be invalid) */
  if( ack_gen->head != ack_gen->tail && acks ) {
    return ack_enc_level;
  }

  /* Check for handshake data to send */
  /* hs_data_empty is used to optimize the test */
  uint peer_enc_level = conn->peer_enc_level;
  if( FD_UNLIKELY( !conn->hs_data_empty ) ) {
    fd_quic_tls_hs_data_t * hs_data   = NULL;

    for( uint i = peer_enc_level; i < 4 && i < enc_level; ++i ) {
      if( enc_level == ~0u || enc_level == i ) {
        hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, i );
        if( hs_data ) {
          /* offset within stream */
          ulong offset = conn->hs_sent_bytes[i];
          /* skip packets we've sent */
          while( hs_data && hs_data->offset + hs_data->data_sz <= offset ) {
            hs_data = fd_quic_tls_get_next_hs_data( conn->tls_hs, hs_data );
          }
          if( hs_data ) {
            enc_level = i;
            return enc_level;
          }
        }
      }
    }

    /* no hs_data was found, so set hs_data_empty */
    conn->hs_data_empty = 1;
  }

  if( enc_level != ~0u ) return enc_level;

  /* handshake done? */
  if( FD_UNLIKELY( conn->handshake_done_send ) ) return fd_quic_enc_level_appdata_id;

  /* find stream data to send */
  fd_quic_tx_stream_t * stream = fd_quic_tx_stream_dlist_ele_peek_head( conn->send_streams, tx_pool );
  if( !fd_quic_tx_stream_dlist_is_empty( conn->send_streams, tx_pool ) && stream->upd_pkt_number >= app_pkt_number ) {
    return fd_quic_enc_level_appdata_id;
  }

  if( conn->flags && conn->upd_pkt_number >= app_pkt_number ) {
    return fd_quic_enc_level_appdata_id;
  }

  /* nothing to send */
  return ~0u;
}

/* handle single v1 frames */
/* returns bytes consumed */
ulong
fd_quic_handle_v1_frame( fd_quic_t *       quic,
                         fd_quic_conn_t *  conn,
                         fd_quic_pkt_t *   pkt,
                         uint              pkt_type,
                         uchar const *     buf,
                         ulong             buf_sz ) {
  if( conn->state == FD_QUIC_CONN_STATE_DEAD ) return FD_QUIC_PARSE_FAIL;

  fd_quic_frame_context_t frame_context[1] = {{ quic, conn, pkt }};

  uchar const * p     = buf;
  uchar const * p_end = buf + buf_sz;

  /* skip padding */
  while( p < p_end && *p == '\x00' ) {
    p++;
  }
  if( p == p_end ) return (ulong)(p - buf);

  /* frame id is first byte */
  uchar id    = *p;
  uchar id_lo = 255; /* allow for fragments to work */
  uchar id_hi = 0;

  /* check whether packet type, frame type combo is allowed */
  if( FD_UNLIKELY( !fd_quic_frame_type_allowed( pkt_type, id ) ) ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

#include "templ/fd_quic_parse_frame.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

  /* unknown frame types are PROTOCOL_VIOLATION errors */
  FD_DEBUG( FD_LOG_DEBUG(( "unexpected frame type: %d  at offset: %ld", (int)*p, (long)( p - buf ) )); )
  fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );

  return FD_QUIC_PARSE_FAIL;
}

fd_quic_t *
fd_quic_fini( fd_quic_t * quic ) {

  if( FD_UNLIKELY( !quic ) ) {
    FD_LOG_WARNING(("NULL quic"));
    return NULL;
  }

  /* Derive memory layout */

  fd_quic_layout_t layout = {0};
  fd_quic_footprint_ext( &quic->limits, &layout );

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Deinit TLS */

  fd_quic_tls_delete( state->tls ); state->tls = NULL;

  /* Delete service queue */

  service_queue_delete( service_queue_leave( state->service_queue ) );
  state->service_queue = NULL;

  /* Delete conn ID map */

  fd_quic_conn_map_delete( fd_quic_conn_map_leave( state->conn_map ) );
  state->conn_map = NULL;

  /* Reset conn free list */

  fd_quic_conn_pool_delete( fd_quic_conn_pool_leave( state->conns ) );
  state->conns = NULL;

  /* Clear join-lifetime memory regions */

  memset( &quic->cb, 0, sizeof( fd_quic_callbacks_t  ) );
  memset( state,     0, sizeof( fd_quic_state_t      ) );

  return quic;
}

void *
fd_quic_delete( fd_quic_t * quic ) {

  if( FD_UNLIKELY( !quic ) ) {
    FD_LOG_WARNING(( "NULL quic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)quic, fd_quic_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned quic" ));
    return NULL;
  }

  if( FD_UNLIKELY( quic->magic!=FD_QUIC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( quic->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)quic;
}

FD_QUIC_API int
fd_quic_stream_uni_send( fd_quic_conn_t * conn,
                         void const *     data,
                         ulong            data_sz ) {
  fd_quic_t *       quic  = conn->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );

  if( FD_UNLIKELY( conn->server ||
                   conn->state != FD_QUIC_CONN_STATE_ACTIVE ||
                   conn->tx_initial_max_stream_data_uni < FD_TXN_MTU ) ) {
    return FD_QUIC_SEND_ERR_INVAL_CONN;
  }

  if( FD_UNLIKELY( data_sz > FD_TXN_MTU ) ) {
    return FD_QUIC_SEND_ERR_OVERSZ;
  }

  ulong stream_id = conn->tx_next_stream_id;

  /* peer imposed limit on streams */
  ulong tx_sup_stream_id = conn->tx_sup_stream_id;
  ulong conn_quota       = conn->tx_max_data - conn->tx_tot_data;
  if( FD_UNLIKELY( stream_id >= tx_sup_stream_id || conn_quota < data_sz ) ) {
    /* this is a normal condition which occurs whenever we run up to
       the peer advertised limit and represents one form of flow control */
    FD_DEBUG( FD_LOG_DEBUG(( "insufficient quota for stream" )); )
    return FD_QUIC_SEND_ERR_QUOTA;
  }

  fd_quic_tx_stream_t * stream = fd_quic_tx_stream_alloc( state->tx_streams, conn, stream_id, data, data_sz );
  if( FD_UNLIKELY( !stream ) ) {
    /* no streams available in the stream pool */
    return FD_QUIC_SEND_ERR_OOM;
  }

  /* wind up for next send */
  conn->tx_tot_data       += data_sz;
  conn->tx_next_stream_id  = stream_id + 4U;

  quic->metrics.stream_opened_cnt++;
  quic->metrics.stream_closed_cnt++;

  /* schedule send */
  fd_quic_reschedule_conn( conn, 0 );

  return FD_QUIC_SUCCESS;
}

/* packet processing */

/* fd_quic_abandon_enc_level frees all resources associated encryption
   levels less or equal to enc_level. */

void
fd_quic_abandon_enc_level( fd_quic_conn_t * conn,
                           uint             enc_level ) {
  fd_quic_state_t * state = fd_quic_get_state( conn->quic );
  if( FD_LIKELY( !fd_uint_extract_bit( conn->keys_avail, (int)enc_level ) ) ) return;
  FD_DEBUG( FD_LOG_DEBUG(( "conn=%p abandoning enc_level=%u", (void *)conn, enc_level )); )

  fd_quic_ack_gen_abandon_enc_level( conn->ack_gen, enc_level );

  fd_quic_pkt_meta_t *      pool = state->pkt_meta_pool;
  fd_quic_pkt_meta_list_t * list = &conn->sent_pkt_meta[enc_level];
  fd_quic_pkt_meta_list_t * free = state->pkt_meta_free;
  for( uint j=0; j<=enc_level; j++ ) {
    conn->keys_avail = fd_uint_clear_bit( conn->keys_avail, (int)j );

    /* treat all packets as ACKed (freeing handshake data, etc.) */
    while( !fd_quic_pkt_meta_list_is_empty( list ) ) {
      fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_list_ele_pop_head( list, pool );
      fd_quic_reclaim_pkt_meta( conn, pkt_meta, j );
      fd_quic_pkt_meta_list_ele_push_head( free, pkt_meta, pool );
    }
  }
}

void
fd_quic_gen_initial_secret_and_keys(
    fd_quic_conn_t *          conn,
    fd_quic_conn_id_t const * dst_conn_id ) {

  fd_quic_gen_initial_secret(
      &conn->secrets,
      dst_conn_id->conn_id, dst_conn_id->sz );

  fd_quic_gen_secrets(
      &conn->secrets,
      fd_quic_enc_level_initial_id ); /* generate initial secrets */

  /* gen initial keys */
  fd_quic_gen_keys(
      &conn->keys[ fd_quic_enc_level_initial_id ][ 0 ],
      conn->secrets.secret[ fd_quic_enc_level_initial_id ][ 0 ] );

  /* gen initial keys */
  fd_quic_gen_keys(
      &conn->keys[ fd_quic_enc_level_initial_id ][ 1 ],
      conn->secrets.secret   [ fd_quic_enc_level_initial_id ][ 1 ] );
}

ulong
fd_quic_send_retry( fd_quic_t *               quic,
                    fd_quic_pkt_t *           pkt,
                    fd_quic_conn_id_t const * orig_dst_conn_id,
                    fd_quic_conn_id_t const * new_conn_id,
                    uchar const               dst_mac_addr_u6[ 6 ],
                    uint                      dst_ip_addr,
                    ushort                    dst_udp_port ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );

  uchar retry_pkt[ FD_QUIC_RETRY_LOCAL_SZ ];
  ulong retry_pkt_sz = fd_quic_retry_create( retry_pkt, pkt, state->_rng, state->retry_secret, state->retry_iv, orig_dst_conn_id, new_conn_id, state->now );

  if( FD_UNLIKELY( fd_quic_tx_buffered_raw(
        quic,
        retry_pkt,
        retry_pkt_sz,
        // encode buffer
        dst_mac_addr_u6,
        &pkt->ip4->net_id,
        dst_ip_addr,
        quic->config.net.listen_udp_port,
        dst_udp_port,
        1 ) == FD_QUIC_FAILED ) ) {
    quic->metrics.conn_err_retry_fail_cnt++;
    return FD_QUIC_PARSE_FAIL;
  };
  return 0UL;
}

/* fd_quic_handle_v1_initial handles an "Initial"-type packet.
   Valid for both server and client.  Initial packets are used to
   establish QUIC conns and wrap the TLS handshake flow among other
   things. */

ulong
fd_quic_handle_v1_initial( fd_quic_t *               quic,
                           fd_quic_conn_t **         p_conn,
                           fd_quic_pkt_t *           pkt,
                           fd_quic_conn_id_t const * conn_id,
                           uchar *                   cur_ptr,
                           ulong                     cur_sz ) {
  fd_quic_conn_t * conn = *p_conn;

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Initial packets are de-facto unencrypted.  Packet protection is
     still applied, albeit with publicly known encryption keys.

     RFC 9001 specifies use of the TLS_AES_128_GCM_SHA256_ID suite for
     initial secrets and keys. */

  uint const enc_level = fd_quic_enc_level_initial_id;

  /* Save the original destination conn ID for later.  In QUIC, peers
     choose their own "conn ID" (more like a peer ID) and indirectly
     instruct the other peer to be addressed as such via the dest conn
     ID field.  However, when the client sends the first packet, it
     doesn't know the preferred dest conn ID to pick for the server
     Thus, the client picks a random dest conn ID -- which is referred
     to as "original dest conn ID". */

  fd_quic_conn_id_t orig_dst_conn_id = *conn_id;

  /* Parse initial packet */

  fd_quic_initial_t initial[1] = {0};
  ulong rc = fd_quic_decode_initial( initial, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_initial failed" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* check bounds on initial */

  /* len indicated the number of bytes after the packet number offset
     so verify this value is within the packet */
  ulong len = (ulong)( initial->pkt_num_pnoff + initial->len );
  if( FD_UNLIKELY( len > cur_sz ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Bogus initial packet length" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* Check it is valid for a token to be present in an initial packet in the current context.

     quic->config.role == FD_QUIC_ROLE_CLIENT
     - Indicates the client received an initial packet with a token from a server. "Initial packets
     sent by the server MUST set the Token Length field to 0; clients that receive an Initial packet
     with a non-zero Token Length field MUST either discard the packet or generate a connection
     error of type PROTOCOL_VIOLATION (RFC 9000, Section 17.2.2)"

     quic->config.retry == false
     - Indicates the server is not configured to retry, but a client attached a token to this
     initial packet. NEW_TOKEN frames are not supported, so this implementation treats the presence
     of a token when retry is disabled as an error. */
  if( FD_UNLIKELY( initial->token_len > 0 &&
                   ( quic->config.role == FD_QUIC_ROLE_CLIENT || !quic->config.retry ) ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Rejecting initial with token" )); )
    return FD_QUIC_PARSE_FAIL;
  }

  /* Initial packets have explicitly encoded conn ID lengths. */

  if( FD_UNLIKELY( ( initial->src_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) |
                   ( initial->dst_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Bogus conn ID length" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* Do we have a conn object for this dest conn ID?
     If not, allocate one. */

  if( FD_UNLIKELY( !conn ) ) {
    if( quic->config.role==FD_QUIC_ROLE_SERVER ) {
      /* According to RFC 9000 Section 14.1, INITIAL packets less than the
         a certain length must be discarded, and the connection may be
         closed.  (Mitigates UDP amplification) */

      if( pkt->datagram_sz < FD_QUIC_INITIAL_PAYLOAD_SZ_MIN ) {
        /* can't trust the included values, so can't reply */
        return FD_QUIC_PARSE_FAIL;
      }

      /* Early check: Is conn free? */

      if( FD_UNLIKELY( !state->conns ) ) {
        FD_DEBUG( FD_LOG_DEBUG(( "ignoring conn request: no free conn slots" )) );
        quic->metrics.conn_err_no_slots_cnt++;
        return FD_QUIC_PARSE_FAIL; /* FIXME better error code? */
      }

      /* Pick a new conn ID for ourselves, which the peer will address us
         with in the future (via dest conn ID). */

      ulong new_conn_id_u64 = fd_rng_ulong( state->_rng );
      fd_quic_conn_id_t new_conn_id = fd_quic_conn_id_new( &new_conn_id_u64, sizeof(ulong) );

      /* Save peer's conn ID, which we will use to address peer with. */

      fd_quic_conn_id_t peer_conn_id = {0};

      fd_memcpy( peer_conn_id.conn_id, initial->src_conn_id, FD_QUIC_MAX_CONN_ID_SZ );
      peer_conn_id.sz = initial->src_conn_id_len;

      /* Save peer's network endpoint */

      ushort dst_udp_port       = pkt->udp->net_sport;
      uint   dst_ip_addr        = FD_LOAD( uint, pkt->ip4->saddr_c );
      uchar  dst_mac_addr_u6[6] = {0};
      memcpy( dst_mac_addr_u6, pkt->eth->src, 6 );

      /* TODO in the case of FD_IP_PROBE_RQD, we should initiate an ARP probe
         But in this case, we don't want to keep a full connection state
         Change this to allow a small queue of pending ARP requests to
         be processed out-of-band */

      /* For now, only supporting QUIC v1.
         QUIC v2 is an active IETF draft as of 2023-Mar:
         https://datatracker.ietf.org/doc/draft-ietf-quic-v2/ */

      uint version = pkt->long_hdr->version;
      if( FD_UNLIKELY( version != 1u ) ) {
        /* FIXME this should already have been checked */
        return FD_QUIC_PARSE_FAIL;
      }

      /* Prepare QUIC-TLS transport params object (sent as a TLS extension).
         Take template from state and mutate certain params in-place.

         See RFC 9000 Section 18 */

      /* TODO Each transport param is a TLV tuple. This allows serializing
         most transport params ahead of time.  Only the conn-specific
         differences will have to be appended here. */

      fd_quic_transport_params_t tp[1] = { state->transport_params };

      /* assume no retry */
      tp->retry_source_connection_id_present = 0;

      /* Send orig conn ID back to client (server only) */

      tp->original_destination_connection_id_present = 1;
      tp->original_destination_connection_id_len     = orig_dst_conn_id.sz;
      fd_memcpy( tp->original_destination_connection_id,
          orig_dst_conn_id.conn_id,
          FD_QUIC_MAX_CONN_ID_SZ );

      /* Repeat the conn ID we picked in transport params (this is done
         to authenticate conn IDs via TLS by including them in TLS-
         protected data).

         Per spec, this field should be the source conn ID field we've set
         on the first Initial packet we've sent.  At this point, we might
         not have sent an Initial packet yet -- so this field should hold
         a value we are about to pick.

         fd_quic_conn_create will set conn->initial_source_conn_id to
         the random new_conn_id we've created earlier. */

      tp->initial_source_connection_id_present = 1;
      tp->initial_source_connection_id_len     = new_conn_id.sz;
      fd_memcpy( tp->initial_source_connection_id,
          new_conn_id.conn_id,
          FD_QUIC_MAX_CONN_ID_SZ );

      /* Handle retry if configured. */
      if( quic->config.retry ) {
        fd_quic_metrics_t * metrics = &quic->metrics;

        /* This is the initial packet before retry. */
        if( initial->token_len == 0 ) {
          /* FIXME we pass the "tp" here to allow the function to add the retry_source_connection_ip
           * transport parameter to be added.
           * This is incorrect, since:
           *   1. "tp" is transient, and will likely be modified before it is encoded into a packet
           *   2. RETRY is supposed to be stateless
           *
           * The fix is thus:
           *   1. put the new source connection id (or some seed from which it's generated)
           *          into the token in the RETRY packet
           *   2. upon receiving the token back in a new INITIAL packet, unpack the connection id
           *          from the token and store in the newly created connection id
           *   3. when the "tp" is about to be encoded, add the "retry_source_connection_ip"
           *          from the appropriate member of "conn" */
          if( FD_UNLIKELY( fd_quic_send_retry(
                quic, pkt,
                &orig_dst_conn_id, &new_conn_id,
                dst_mac_addr_u6, dst_ip_addr, dst_udp_port ) ) ) {
            return FD_QUIC_FAILED;
          }
          return (initial->pkt_num_pnoff + initial->len);
        }

        /* This Initial packet is in response to our Retry.
           Validate the relevant fields of this post-retry INITIAL packet,
           i.e. retry src conn id, ip, port */

        fd_quic_conn_id_t retry_src_conn_id;
        int retry_ok = fd_quic_retry_server_verify( pkt, initial, &orig_dst_conn_id, &retry_src_conn_id, state->retry_secret, state->retry_iv, state->now );
        if( FD_UNLIKELY( retry_ok!=FD_QUIC_SUCCESS ) ) {
          metrics->conn_err_retry_fail_cnt++;
          /* No need to set conn error, no conn object exists */
          return FD_QUIC_PARSE_FAIL;
        };

        /* From rfc 9000:

	      Figure 8 shows a similar handshake that includes a Retry packet.

	      Client                                                  Server
	      Initial: DCID=S1, SCID=C1 ->
						  <- Retry: DCID=C1, SCID=S2
	      Initial: DCID=S2, SCID=C1 ->
						<- Initial: DCID=C1, SCID=S3
					   ...
	      1-RTT: DCID=S3 ->
							   <- 1-RTT: DCID=C1

	      Figure 8: Use of Connection IDs in a Handshake with Retry
	      In both cases (Figures 7 and 8), the client sets the value of the initial_source_connection_id
		  transport parameter to C1.

	      When the handshake does not include a Retry (Figure 7), the server sets
		  original_destination_connection_id to S1 (note that this value is chosen by the client) and
		  initial_source_connection_id to S3. In this case, the server does not include a
                  retry_source_connection_id transport parameter.

              When the handshake includes a Retry (Figure 8), the server sets
                  original_destination_connection_id to S1, retry_source_connection_id
                  to S2, and initial_source_connection_id to S3.  */
        tp->original_destination_connection_id_present = 1;
        tp->original_destination_connection_id_len     = orig_dst_conn_id.sz;
        memcpy( tp->original_destination_connection_id,
                orig_dst_conn_id.conn_id,
                orig_dst_conn_id.sz );

        /* Client echoes back the SCID we sent via Retry.  Safe to trust because we signed the Retry Token
           (Length and content validated in fd_quic_retry_server_verify) */
        tp->retry_source_connection_id_present = 1;
        tp->retry_source_connection_id_len     = FD_QUIC_CONN_ID_SZ;
        memcpy( tp->retry_source_connection_id, retry_src_conn_id.conn_id, FD_QUIC_CONN_ID_SZ );

        metrics->conn_retry_cnt++;
      }

      /* Allocate new conn */

      conn = fd_quic_conn_create( quic,
          new_conn_id_u64,
          &peer_conn_id,
          dst_ip_addr,
          dst_udp_port,
          1,            /* server */
          version );    /* version */

      if( FD_UNLIKELY( !conn ) ) { /* no free connections */
        /* TODO send failure back to origin? */
        /* FIXME unreachable? conn_cnt already checked above */
        FD_DEBUG( FD_LOG_WARNING( ( "failed to allocate QUIC conn" ) ) );
        return FD_QUIC_PARSE_FAIL;
      }

      /* keep orig_dst_conn_id */
      conn->orig_dst_conn_id = orig_dst_conn_id;

      /* set the value for the caller */
      *p_conn = conn;

      /* if we fail after here, we must reap the connection
         TODO maybe actually set the connection to reset, and clean up resources later */

      /* Create a TLS handshake */

      fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
          state->tls,
          (void*)conn,
          1 /*is_server*/,
          quic->config.sni,
          tp );
      if( FD_UNLIKELY( !tls_hs ) ) {
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        fd_quic_reschedule_conn( conn, 0 );
        quic->metrics.conn_aborted_cnt++;
        quic->metrics.hs_err_alloc_fail_cnt++;
        FD_DEBUG( FD_LOG_WARNING(( "fd_quic_tls_hs_new failed" )) );
        return FD_QUIC_PARSE_FAIL;
      }
      conn->tls_hs = tls_hs;

      fd_quic_gen_initial_secret_and_keys( conn, conn_id );
    } else {
      /* connection may have been torn down */
      FD_DEBUG( FD_LOG_DEBUG(( "unknown connection ID" )); )
      return FD_QUIC_PARSE_FAIL;
    }
  }

  if( FD_UNLIKELY( !fd_uint_extract_bit( conn->keys_avail, (int)enc_level ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* Decrypt incoming packet */

  /* header protection needs the offset to the packet number */
  ulong   pn_offset        = initial->pkt_num_pnoff;

  ulong   body_sz          = initial->len;  /* not a protected field */
                                             /* length of payload + num packet bytes */

  ulong   pkt_number       = (ulong)ULONG_MAX;
  ulong   pkt_number_sz    = (ulong)ULONG_MAX;
  ulong   tot_sz           = (ulong)ULONG_MAX;

    /* this decrypts the header */
    int server = conn->server;

    if( FD_UNLIKELY(
          fd_quic_crypto_decrypt_hdr( cur_ptr, cur_sz,
                                      pn_offset,
                                      &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) ) {
      /* As this is an INITIAL packet, change the status to DEAD, and allow
         it to be reaped */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt_hdr failed" )) );
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      fd_quic_reschedule_conn( conn, 0 );
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* number of bytes in the packet header */
    pkt_number_sz = ( (uint)cur_ptr[0] & 0x03u ) + 1u;
    tot_sz        = pn_offset + body_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    pkt_number = fd_quic_parse_bits( cur_ptr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* NOTE from rfc9002 s3
       It is permitted for some packet numbers to never be used, leaving intentional gaps. */
    /* this decrypts the header and payload */
    if( FD_UNLIKELY(
          fd_quic_crypto_decrypt( cur_ptr, tot_sz,
                                  pn_offset,
                                  pkt_number,
                                  &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

  if( FD_UNLIKELY( body_sz < pkt_number_sz + FD_QUIC_CRYPTO_TAG_SZ ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* check if reply conn id needs to change */
  if( FD_UNLIKELY( !( conn->server | conn->established ) ) ) {
    /* switch to the source connection id for future replies */

    /* replace peer 0 connection id */
               conn->peer[0].conn_id.sz =     initial->src_conn_id_len;
    fd_memcpy( conn->peer[0].conn_id.conn_id, initial->src_conn_id, FD_QUIC_MAX_CONN_ID_SZ );

    /* don't repeat this procedure */
    conn->established = 1;
  }

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = cur_ptr + payload_off;
  ulong         frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic,
                                  conn,
                                  pkt,
                                  FD_QUIC_PKT_TYPE_INITIAL,
                                  frame_ptr,
                                  frame_sz );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc==0UL || rc>frame_sz ) ) {
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame, and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = state->now;
  conn->flags &= ~( FD_QUIC_CONN_FLAGS_PING_SENT | FD_QUIC_CONN_FLAGS_PING );

  /* update expected packet number */
  do {
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    ulong next_pkt_number = pkt_number  + 1UL;
    conn->exp_pkt_number[pn_space] = fd_ulong_max( conn->exp_pkt_number[pn_space], next_pkt_number );
  } while(0);

  FD_DEBUG( FD_LOG_DEBUG(( "new connection success" )) );

  /* insert into service queue */
  fd_quic_reschedule_conn( conn, 0 );

  /* return number of bytes consumed */
  return tot_sz;
}

ulong
fd_quic_handle_v1_handshake(
    fd_quic_t *      quic,
    fd_quic_conn_t * conn,
    fd_quic_pkt_t *  pkt,
    uchar *          cur_ptr,
    ulong            cur_sz
) {
  uint const enc_level = fd_quic_enc_level_handshake_id;

  if( FD_UNLIKELY( !conn ) ) {
    /* this can happen */
    return FD_QUIC_PARSE_FAIL;
  }

  if( FD_UNLIKELY( !fd_uint_extract_bit( conn->keys_avail, (int)enc_level ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* do parse here */
  fd_quic_handshake_t handshake[1];
  ulong rc = fd_quic_decode_handshake( handshake, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;

  if( FD_UNLIKELY( ( handshake->src_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) |
                   ( handshake->dst_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* check bounds on handshake */

  /* len indicated the number of bytes after the packet number offset
     so verify this value is within the packet */
  ulong len = (ulong)( handshake->pkt_num_pnoff + handshake->len );
  if( FD_UNLIKELY( len > cur_sz ) ) return FD_QUIC_PARSE_FAIL;

  /* decryption */

  /* header protection needs the offset to the packet number */
  ulong    pn_offset        = handshake->pkt_num_pnoff;

  ulong    body_sz          = handshake->len;  /* not a protected field */
                                               /* length of payload + num packet bytes */

  ulong    pkt_number       = (ulong)-1;
  ulong    pkt_number_sz    = (ulong)-1;
  ulong    tot_sz           = (ulong)-1;

  /* this decrypts the header */
  int server = conn->server;

  if( FD_UNLIKELY(
        fd_quic_crypto_decrypt_hdr( cur_ptr, cur_sz,
                                    pn_offset,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) ) {
    quic->metrics.conn_err_tls_fail_cnt++;
    return FD_QUIC_PARSE_FAIL;
  }

  /* number of bytes in the packet header */
  pkt_number_sz = ( (uint)cur_ptr[0] & 0x03u ) + 1u;
  tot_sz        = pn_offset + body_sz; /* total including header and payload */

  /* now we have decrypted packet number */
  pkt_number = fd_quic_parse_bits( cur_ptr + pn_offset, 0, 8u * pkt_number_sz );

  /* packet number space */
  uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

  /* reconstruct packet number */
  fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

  /* set packet number on the context */
  pkt->pkt_number = pkt_number;

  /* NOTE from rfc9002 s3
    It is permitted for some packet numbers to never be used, leaving intentional gaps. */

  /* this decrypts the header and payload */
  if( FD_UNLIKELY(
        fd_quic_crypto_decrypt( cur_ptr, tot_sz,
                                pn_offset,
                                pkt_number,
                                &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) ) {
    /* remove connection from map, and insert into free list */
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
    quic->metrics.conn_err_tls_fail_cnt++;
    return FD_QUIC_PARSE_FAIL;
  }

  /* check body size large enough for required elements */
  if( FD_UNLIKELY( body_sz < pkt_number_sz + FD_QUIC_CRYPTO_TAG_SZ ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* RFC 9000 Section 17.2.2.1. Abandoning Initial Packets
     > A server stops sending and processing Initial packets when it
     > receives its first Handshake packet. */
  fd_quic_abandon_enc_level( conn, fd_quic_enc_level_initial_id );
  if( FD_UNLIKELY( enc_level > conn->peer_enc_level ) ) {
    conn->peer_enc_level = enc_level;
  }

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = cur_ptr + payload_off;
  ulong         frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic,
                                  conn,
                                  pkt,
                                  FD_QUIC_PKT_TYPE_HANDSHAKE,
                                  frame_ptr,
                                  frame_sz );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc == 0UL || rc > frame_sz ) ) {
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = fd_quic_get_state( quic )->now;
  conn->flags &= ~( FD_QUIC_CONN_FLAGS_PING_SENT | FD_QUIC_CONN_FLAGS_PING );

  /* update expected packet number */
  do {
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    ulong next_pkt_number = pkt_number  + 1UL;
    conn->exp_pkt_number[pn_space] = fd_ulong_max( conn->exp_pkt_number[pn_space], next_pkt_number );
  } while(0);

  /* return number of bytes consumed */
  return tot_sz;
}

ulong
fd_quic_handle_v1_retry(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t const * pkt,
    uchar const *         cur_ptr,
    ulong                 cur_sz
) {
  (void)pkt;

  if( FD_UNLIKELY ( quic->config.role == FD_QUIC_ROLE_SERVER ) ) {
    if( FD_UNLIKELY( conn ) ) { /* likely a misbehaving client w/o a conn */
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    }
    return FD_QUIC_PARSE_FAIL;
  }

  if( FD_UNLIKELY( !conn ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  fd_quic_conn_id_t const * orig_dst_conn_id = &conn->peer[0].conn_id;
  uchar const *             retry_token      = NULL;
  ulong                     retry_token_sz   = 0UL;

  int rc = fd_quic_retry_client_verify(
      cur_ptr, cur_sz,
      orig_dst_conn_id,
      &conn->retry_src_conn_id,
      &retry_token, &retry_token_sz
  );
  if( FD_UNLIKELY( rc!=FD_QUIC_SUCCESS ) ) {
    quic->metrics.conn_err_retry_fail_cnt++;
    return FD_QUIC_PARSE_FAIL;
  }

  /* Update the peer using the retry src conn id */
  fd_quic_endpoint_t * peer = &conn->peer[conn->cur_peer_idx];
  peer->conn_id = conn->retry_src_conn_id;

  /* Re-send the ClientHello */
  conn->hs_sent_bytes[fd_quic_enc_level_initial_id] = 0;

  /* Need to regenerate keys using the retry source connection id */
  fd_quic_gen_initial_secret_and_keys( conn, &conn->retry_src_conn_id );

  /* The token length is the remaining bytes in the retry packet after subtracting known fields. */
  conn->token_len = retry_token_sz;
  fd_memcpy( &conn->token, retry_token, conn->token_len );

  /* have to rewind the handshake data */
  uint enc_level                 = 0;
  conn->hs_sent_bytes[enc_level] = 0;
  conn->hs_data_empty            = 0;

  /* send the INITIAL */
  conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;

  fd_quic_reschedule_conn( conn, 0 );

  return cur_sz;
}

ulong
fd_quic_handle_v1_zero_rtt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t const * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;
  /* since we do not support zero-rtt, simply fail the packet */
  if( conn ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR, __LINE__ );
  }
  return FD_QUIC_PARSE_FAIL;
}

ulong
fd_quic_handle_v1_one_rtt( fd_quic_t *           quic,
                           fd_quic_conn_t *      conn,
                           fd_quic_pkt_t *       pkt,
                           uchar *         const cur_ptr,
                           ulong           const tot_sz ) {
  if( !conn ) {
    /* this can happen */
    return FD_QUIC_PARSE_FAIL;
  }

  /* encryption level for one_rtt is "appdata" */
  uint const enc_level = fd_quic_enc_level_appdata_id;

  /* set on pkt for future processing */
  pkt->enc_level = enc_level;

  fd_quic_one_rtt_t one_rtt[1];

  /* hidden field needed by decode function */
  one_rtt->dst_conn_id_len = 8;

  ulong rc = fd_quic_decode_one_rtt( one_rtt, cur_ptr, tot_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    FD_DEBUG( FD_LOG_DEBUG(( "1-RTT: failed to decode" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* generate one_rtt secrets, keys etc */

  if( FD_UNLIKELY( !fd_uint_extract_bit( conn->keys_avail, (int)enc_level ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* decryption */

  /* header protection needs the offset to the packet number */
  ulong pn_offset        = one_rtt->pkt_num_pnoff;

  ulong pkt_number       = ULONG_MAX;
  ulong pkt_number_sz    = ULONG_MAX;

    /* this decrypts the header */
    int server = conn->server;

    if( FD_UNLIKELY(
          fd_quic_crypto_decrypt_hdr( cur_ptr, tot_sz,
                                      pn_offset,
                                      &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt_hdr failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

    /* get first byte for future use */
    uint first = (uint)cur_ptr[0];

    /* number of bytes in the packet header */
    pkt_number_sz = ( first & 0x03u ) + 1u;

    /* now we have decrypted packet number */
    pkt_number = fd_quic_parse_bits( cur_ptr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* since the packet number is greater than the highest last seen,
       do spin bit processing */
    /* TODO by spec 1 in 16 connections should have this disabled */
    uint spin_bit = first & (1u << 6u);
    conn->spin_bit = (uchar)(0xFF&( spin_bit ^ ( (uint)conn->server ^ 1u ) ));

    /* fetch key phase after decrypting header */
    uint key_phase = ( first >> 2u ) & 1u;

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* NOTE from rfc9002 s3
      It is permitted for some packet numbers to never be used, leaving intentional gaps. */

    /* is current packet in the current key phase? */
    int current_key_phase = conn->key_phase == key_phase;

    /* is this a new request to change key_phase? */
    if( !current_key_phase && !conn->key_phase_upd ) {
      FD_DEBUG( FD_LOG_DEBUG(( "key update started" )); )

      /* generate new secrets */
      fd_quic_gen_new_secrets( &conn->secrets );

      /* generate new keys */
      fd_quic_gen_new_keys( &conn->new_keys[0],
                            conn->secrets.new_secret[0] );
      fd_quic_gen_new_keys( &conn->new_keys[1],
                            conn->secrets.new_secret[1] );
      conn->key_phase_upd = 1;
    }

    fd_quic_crypto_keys_t * keys = current_key_phase ? &conn->keys[enc_level][!server]
                                                     : &conn->new_keys[!server];

    /* this decrypts the header and payload */
    if( FD_UNLIKELY(
          fd_quic_crypto_decrypt( cur_ptr, tot_sz,
                                  pn_offset,
                                  pkt_number,
                                  keys ) != FD_QUIC_SUCCESS ) ) {
      /* remove connection from map, and insert into free list */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

  if( FD_UNLIKELY( enc_level > conn->peer_enc_level ) ) {
    conn->peer_enc_level = enc_level;
  }

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = cur_ptr + payload_off;
  ulong         frame_sz    = tot_sz - pn_offset - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic,
                                  conn,
                                  pkt,
                                  FD_QUIC_PKT_TYPE_ONE_RTT,
                                  frame_ptr,
                                  frame_sz );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "frame failed to parse" )) );
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc == 0UL || rc > frame_sz ) ) {
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame, and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = fd_quic_get_state( quic )->now;
  conn->flags &= ~( FD_QUIC_CONN_FLAGS_PING_SENT | FD_QUIC_CONN_FLAGS_PING );

  /* update expected packet number */
  do {
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    ulong next_pkt_number = pkt_number  + 1UL;
    conn->exp_pkt_number[pn_space] = fd_ulong_max( conn->exp_pkt_number[pn_space], next_pkt_number );
  } while(0);

  return tot_sz;
}

void
fd_quic_schedule_conn( fd_quic_conn_t * conn ) {

  fd_quic_t *       quic    = conn->quic;
  fd_quic_state_t * state   = fd_quic_get_state( quic );

  ulong             timeout = conn->next_service_time;

  /* scheduled? */
  if( conn->in_service ) {
    /* find conn in events, then remove, update, insert */
    fd_quic_event_t * event     = NULL;
    ulong             event_idx = 0;
    ulong             cnt   = service_queue_cnt( state->service_queue );
    for( ulong j = 0; j < cnt; ++j ) {
      fd_quic_event_t * cur_event = state->service_queue + j;
      if( cur_event->conn == conn ) {
        event     = cur_event;
        event_idx = j;
        break;
      }
    }

    if( FD_LIKELY( event ) ) {
      /* remove key */
      service_queue_remove( state->service_queue, event_idx );

      /* TODO can use a priority queue key-reduce operation, which may be done more
         quickly than remove, insert */
    }
  }

  timeout = fd_ulong_max( timeout, state->now + 1UL );

  /* insert key */
  fd_quic_event_t event[1] = {{ .timeout = timeout, .conn = conn }};
  service_queue_insert( state->service_queue, event );

  conn->sched_service_time = timeout;
  conn->next_service_time  = timeout;
  conn->in_service         = 1;

  FD_DEBUG(
    ulong now = fd_quic_get_state( conn->quic )->now;
    FD_LOG_DEBUG(( "conn=%p scheduled in %g ns", (void *)conn, (double)fd_ulong_if( timeout>now, timeout-now, 0 ) ));
  )
}

void
fd_quic_reschedule_conn( fd_quic_conn_t * conn,
                         ulong            timeout ) {
  fd_quic_t *       quic  = conn->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong now = state->now;

  timeout = fd_ulong_max( timeout, now + 1UL ); /* ??? */

  /* scheduled? */
  if( conn->in_service ) {
    timeout = fd_ulong_min( timeout, conn->next_service_time );

    /* in the queue, but already scheduled sooner */
    if( timeout >= conn->sched_service_time ) {
      return;
    }

    /* find conn in events, then remove, update, insert */
    fd_quic_event_t * event     = NULL;
    ulong             event_idx = 0;
    ulong             cnt   = service_queue_cnt( state->service_queue );
    for( ulong j = 0; j < cnt; ++j ) {
      fd_quic_event_t * cur_event = state->service_queue + j;
      if( cur_event->conn == conn ) {
        event     = cur_event;
        event_idx = j;
        break;
      }
    }

    if( FD_LIKELY( event ) ) {
      /* remove key */
      service_queue_remove( state->service_queue, event_idx );

      /* TODO can use a priority queue key-reduce operation, which may be done more
         quickly than remove, insert */
    }

    conn->next_service_time = timeout;
    fd_quic_schedule_conn( conn );

    return;
  }

  /* since we're not in the service queue, just set the next_service_time */
  conn->next_service_time = timeout;
}

/* process v1 quic packets
   only called for packets with long header
   returns number of bytes consumed, or FD_QUIC_PARSE_FAIL upon error
   assumes cur_sz >= FD_QUIC_SHORTEST_PKT */
ulong
fd_quic_process_quic_packet_v1( fd_quic_t *     quic,
                                fd_quic_pkt_t * pkt,
                                uchar *         cur_ptr,
                                ulong           cur_sz ) {

  /* do not respond to packets over 1500 bytes */
  if( FD_UNLIKELY( cur_sz > 1500 ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  fd_quic_state_t *    state = fd_quic_get_state( quic );
  fd_quic_conn_map_t * entry = NULL;
  fd_quic_conn_t *     conn  = NULL;

  if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* keep end */
  uchar * orig_ptr = cur_ptr;

  fd_quic_common_hdr_t common_hdr[1];
  ulong rc = fd_quic_decode_common_hdr( common_hdr, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_common_hdr failed" )); )
    return FD_QUIC_PARSE_FAIL;
  }

  /* TODO simplify, as this function only called for long_hdr packets now */
  /* hdr_form is 1 bit */
  if( common_hdr->hdr_form == 1 ) { /* long header */

    fd_quic_long_hdr_t * long_hdr = pkt->long_hdr;
    rc = fd_quic_decode_long_hdr( long_hdr, cur_ptr+1, cur_sz-1 );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_long_hdr failed" )); )
      return FD_QUIC_PARSE_FAIL;
    }

    /* extract the dst connection id */
    fd_quic_conn_id_t dst_conn_id = fd_quic_conn_id_new( long_hdr->dst_conn_id, long_hdr->dst_conn_id_len );
    if( dst_conn_id.sz == FD_QUIC_CONN_ID_SZ ) {
      entry = fd_quic_conn_map_query( state->conn_map, fd_ulong_load_8( dst_conn_id.conn_id ), NULL );
      conn  = entry ? state->conns + entry->conn_idx : NULL;
    }

    /* encryption level matches that of TLS */
    pkt->enc_level = common_hdr->long_packet_type; /* V2 uses an indirect mapping */

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* long_packet_type is 2 bits, so only four possibilities */
    switch( common_hdr->long_packet_type ) {
      case FD_QUIC_PKTTYPE_V1_INITIAL:
        rc = fd_quic_handle_v1_initial( quic, &conn, pkt, &dst_conn_id, cur_ptr, cur_sz );
        if( FD_UNLIKELY( !conn ) ) {
          /* FIXME not really a fail - Could be a retry */
          return FD_QUIC_PARSE_FAIL;
        }
        break;
      case FD_QUIC_PKTTYPE_V1_HANDSHAKE:
        rc = fd_quic_handle_v1_handshake( quic, conn, pkt, cur_ptr, cur_sz );
        break;
      case FD_QUIC_PKTTYPE_V1_RETRY:
        rc = fd_quic_handle_v1_retry( quic, conn, pkt, cur_ptr, cur_sz );
        break;
      case FD_QUIC_PKTTYPE_V1_ZERO_RTT:
        rc = fd_quic_handle_v1_zero_rtt( quic, conn, pkt, cur_ptr, cur_sz );
        break;
    }

    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "Rejected packet (type=%d)", common_hdr->long_packet_type )); )
      return FD_QUIC_PARSE_FAIL;
    }

  } else { /* short header */
    /* encryption level of short header packets is fd_quic_enc_level_appdata_id */
    pkt->enc_level = fd_quic_enc_level_appdata_id;

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* find connection id */
    ulong dst_conn_id = fd_ulong_load_8( cur_ptr+1 );
    entry = fd_quic_conn_map_query( state->conn_map, dst_conn_id, NULL );
    if( FD_UNLIKELY( !entry ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "one_rtt failed: unknown conn ID %#lx", dst_conn_id )) );
      return FD_QUIC_PARSE_FAIL;
    }

    conn = state->conns + entry->conn_idx;
    rc = fd_quic_handle_v1_one_rtt( quic, conn, pkt, cur_ptr, cur_sz );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      return FD_QUIC_PARSE_FAIL;
    }
  }

  if( FD_UNLIKELY( rc == 0UL ) ) {
    /* this is an error because it causes infinite looping */
    return FD_QUIC_PARSE_FAIL;
  }

  /* if we get here we parsed all the frames, so ack the packet */
  fd_quic_ack_pkt( conn->ack_gen, &quic->config, pkt, state->now, state->_rng );
  ulong ack_schedule = fd_quic_ack_gen_next_wakeup( conn->ack_gen, &quic->config, state->now );
  FD_DEBUG( FD_LOG_DEBUG(( "conn=%p scheduled in %g ns (ACK)", (void *)conn, (double)fd_ulong_if( ack_schedule>state->now, ack_schedule-state->now, 0 ) )) );
  fd_quic_reschedule_conn( conn, ack_schedule );

  cur_ptr += rc;

  /* return bytes consumed */
  return (ulong)( cur_ptr - orig_ptr );
}

void
fd_quic_process_packet( fd_quic_t * quic,
                        uchar *     data,
                        ulong       data_sz ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong rc = 0;

  /* holds the remainder of the packet*/
  uchar * cur_ptr = data;
  ulong   cur_sz  = data_sz;

  if( FD_UNLIKELY( data_sz > 0xffffu ) ) {
    /* sanity check */
    return;
  }

  fd_quic_pkt_t pkt = { .datagram_sz = (uint)data_sz };

  pkt.rcv_time = state->now;

  /* parse eth, ip, udp */
  rc = fd_quic_decode_eth( pkt.eth, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    /* TODO count failure */
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_eth failed" )) );
    return;
  }

  /* TODO support for vlan? */

  if( FD_UNLIKELY( pkt.eth->net_type != FD_ETH_HDR_TYPE_IP ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Invalid ethertype: %4.4x", pkt.eth->net_type )) );
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_ip4( pkt.ip4, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    /* TODO count failure */
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_ip4 failed" )) );
    return;
  }

  /* check version, tot_len, protocol, checksum? */
  if( FD_UNLIKELY( pkt.ip4->protocol != FD_IP4_HDR_PROTOCOL_UDP ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Packet is not UDP" )) );
    return;
  }

  /* verify ip4 packet isn't truncated
   * AF_XDP can silently do this */
  if( FD_UNLIKELY( pkt.ip4->net_tot_len > cur_sz ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "IPv4 header indicates truncation" )) );
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_udp( pkt.udp, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    /* TODO count failure  */
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_udp failed" )) );
    return;
  }

  /* sanity check udp length */
  if( FD_UNLIKELY( pkt.udp->net_len < sizeof(fd_udp_hdr_t) ||
                   pkt.udp->net_len > cur_sz ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "UDP header indicates truncation" )) );
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz   = pkt.udp->net_len - rc; /* replace with udp length */

  /* cur_ptr[0..cur_sz-1] should be payload */

  /* filter */
  /*   check dst eth address, ip address? probably not necessary */
  /* usually look up port here, but let's jump straight into decoding as-if
     quic */

  /* check version */
  /* TODO determine whether every quic packet in a udp packet must have the
     same version */
  /* done within loop at present */

  /* update counters */

  /* shortest valid quic payload? */
  if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Undersize QUIC packet" )) );
    return;
  }

  /* check version */

  /* short packets don't have version */
  int long_pkt = !!( (uint)cur_ptr[0] & 0x80u );

  /* version at offset 1..4 */
  uint version = 0;

  if( long_pkt ) {
    version = fd_uint_bswap( FD_LOAD( uint, cur_ptr + 1 ) );

    /* version negotiation packet has version 0 */
    if( version == 0 ) {
      /* TODO implement version negotiation */
      FD_DEBUG( FD_LOG_DEBUG(( "Got version negotiation packet" )) );
      return;
    }

    /* 0x?a?a?a?au is intended to force version negotiation
       TODO implement */
    if( ( version & 0x0a0a0a0au ) == 0x0a0a0a0au ) {
      /* at present, ignore */
      FD_DEBUG( FD_LOG_DEBUG(( "Got version negotiation packet (forced)" )) );
      return;
    }

    if( version != 1 ) {
      /* cannot interpret length, so discard entire packet */
      /* TODO send version negotiation */
      FD_DEBUG( FD_LOG_DEBUG(( "Got unknown version QUIC packet" )) );
      return;
    }

    /* multiple QUIC packets in a UDP packet */
    /* shortest valid quic payload? */
    ulong pkt_idx;
    for( pkt_idx=0UL; pkt_idx<FD_QUIC_PKT_COALESCE_LIMIT; pkt_idx++ ) {
      /* Are we done? Omit short packet handling that follows */
      if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) return;

      /* short packet requires different handling */
      int short_pkt = !( (uint)cur_ptr[0] & 0x80u );

      if( FD_UNLIKELY( short_pkt ) ) break;

      /* check version */
      uint cur_version = fd_uint_bswap( FD_LOAD( uint, cur_ptr + 1 ) );

      if( cur_version != version ) {
        /* multiple versions in a single connection is a violation, and by
           extension so is multiple versions in a single udp datagram
           these are silently ignored

           for reference
             all quic packets in a udp datagram must be for the same connection id
               (section 12.2) and therefore the same connection
             all packets on a connection must be of the same version (5.2) */
        FD_DEBUG( FD_LOG_DEBUG(( "Mixed QUIC versions in packet" )) );
        return;
      }

      /* probably it's better to switch outside the loop */
      switch( version ) {
        case 1u:
          rc = fd_quic_process_quic_packet_v1( quic, &pkt, cur_ptr, cur_sz );
          break;

        /* this is redundant */
        default:
          return;
      }

      /* 0UL means no progress, so fail */
      if( FD_UNLIKELY( ( rc == FD_QUIC_PARSE_FAIL ) |
                       ( rc == 0UL ) )) {
        FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_process_quic_packet_v1 failed (stuck=%d)", rc==0UL )) );
        return;
      }

      if( FD_UNLIKELY( rc > cur_sz ) ) {
        FD_DEBUG( FD_LOG_WARNING(( "fd_quic_process_quic_packet_v1 read too much" )) );
        return;
      }

      /* return code (rc) is the number of bytes consumed */
      cur_sz  -= rc;
      cur_ptr += rc;
    }
    if( pkt_idx==FD_QUIC_PKT_COALESCE_LIMIT ) {
      /* too many packets in a single udp datagram */
      return;
    }
  }

  /* above can drop out of loop if a short packet is detected */
  if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) return;

  /* short header packet
     only one_rtt packets currently have short headers */
  fd_quic_process_quic_packet_v1( quic, &pkt, cur_ptr, cur_sz );
}

/* main receive-side entry point */
int
fd_quic_aio_cb_receive( void *                    context,
                        fd_aio_pkt_info_t const * batch,
                        ulong                     batch_cnt,
                        ulong *                   opt_batch_idx,
                        int                       flush ) {
  (void)flush;

  fd_quic_t *       quic  = (fd_quic_t*)context;
  fd_quic_state_t * state = fd_quic_get_state( quic );

  state->now = fd_quic_now( quic );

  FD_DEBUG(
    static ulong t0 = 0;
    static ulong t1 = 0;
    t0 = state->now;
  )

  /* this aio interface is configured as one-packet per buffer
     so batch[0] refers to one buffer
     as such, we simply forward each individual packet to a handling function */
  for( ulong j = 0; j < batch_cnt; ++j ) {
    fd_quic_process_packet( quic, batch[ j ].buf, batch[ j ].buf_sz );
    quic->metrics.net_rx_byte_cnt += batch[ j ].buf_sz;
  }

  /* the assumption here at present is that any packet that could not be processed
     is simply dropped
     hence, all packets were consumed */
  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  quic->metrics.net_rx_pkt_cnt += batch_cnt;

  FD_DEBUG(
    t1 = fd_quic_now( quic );
    ulong delta = t1 - t0;
    if( delta > (ulong)500e3 ) {
      FD_LOG_WARNING(( "CALLBACK - took %lu  t0: %lu  t1: %lu  batch_cnt: %lu", delta, t0, t1, (ulong)batch_cnt ));
    }
  )

  return FD_AIO_SUCCESS;
}

void
fd_quic_tls_cb_alert( fd_quic_tls_hs_t * hs,
                      void *             context,
                      int                alert ) {
  (void)hs;
  fd_quic_conn_t * conn = (fd_quic_conn_t *)context;
  (void)conn;
  (void)alert;
  FD_DEBUG( FD_LOG_DEBUG(( "TLS callback: %s", conn->server ? "SERVER" : "CLIENT" ));
            FD_LOG_DEBUG(( "TLS alert: (%d-%s)", alert, fd_tls_alert_cstr( (uint)alert ) )); );

  /* TODO store alert to reply to peer */
}

void
fd_quic_tls_cb_secret( fd_quic_tls_hs_t *           hs,
                       void *                       context,
                       fd_quic_tls_secret_t const * secret ) {

  fd_quic_conn_t *  conn   = (fd_quic_conn_t*)context;
  fd_quic_t *       quic   = conn->quic;
  int               server = conn->server;

  /* look up suite */
  /* set secrets */
  FD_TEST( secret->enc_level < FD_QUIC_NUM_ENC_LEVELS );

  uint enc_level = secret->enc_level;

  fd_quic_crypto_secrets_t * crypto_secret = &conn->secrets;

  memcpy( crypto_secret->secret[enc_level][!server], secret->read_secret,  FD_QUIC_SECRET_SZ );
  memcpy( crypto_secret->secret[enc_level][ server], secret->write_secret, FD_QUIC_SECRET_SZ );

  conn->keys_avail = fd_uint_set_bit( conn->keys_avail, (int)enc_level );

  /* gen local keys */
  fd_quic_gen_keys(
      &conn->keys[enc_level][0],
      conn->secrets.secret[enc_level][0] );

  /* gen peer keys */
  fd_quic_gen_keys(
      &conn->keys[enc_level][1],
      conn->secrets.secret[enc_level][1] );

  /* Key logging */

  void *                  keylog_ctx = quic->cb.quic_ctx;
  fd_quic_cb_tls_keylog_t keylog_fn  = quic->cb.tls_keylog;
  if( FD_UNLIKELY( keylog_fn ) ) {
    /* Ignore stdout, stderr, stdin */

    uchar const * recv_secret = secret->read_secret;
    uchar const * send_secret = secret->write_secret;

    uchar const * client_secret = hs->is_server ? recv_secret : send_secret;
    uchar const * server_secret = hs->is_server ? send_secret : recv_secret;

    char buf[256];
    char * s;
    switch( enc_level ) {
    case FD_TLS_LEVEL_HANDSHAKE:
      /*     0 chars */ s = fd_cstr_init( buf );
      /*  0+32 chars */ s = fd_cstr_append_cstr( s, "CLIENT_HANDSHAKE_TRAFFIC_SECRET " );
      /* 32+64 chars */ s = fd_hex_encode( s, hs->hs.base.client_random, 32UL );
      /* 96+ 1 chars */ s = fd_cstr_append_char( s, ' ' );
      /* 97+64 chars */ s = fd_hex_encode( s, client_secret, 32UL );
      /*   161 chars */     fd_cstr_fini( s );
      keylog_fn( keylog_ctx, buf );
      /*     0 chars */ s = fd_cstr_init( buf );
      /*  0+32 chars */ s = fd_cstr_append_cstr( s, "SERVER_HANDSHAKE_TRAFFIC_SECRET " );
      /* 32+64 chars */ s = fd_hex_encode( s, hs->hs.base.client_random, 32UL );
      /* 96+ 1 chars */ s = fd_cstr_append_char( s, ' ' );
      /* 97+64 chars */ s = fd_hex_encode( s, server_secret, 32UL );
      /*   161 chars */     fd_cstr_fini( s );
      keylog_fn( keylog_ctx, buf );
      break;
    case FD_TLS_LEVEL_APPLICATION:
      /*     0 chars */ s = fd_cstr_init( buf );
      /*  0+24 chars */ s = fd_cstr_append_cstr( s, "CLIENT_TRAFFIC_SECRET_0 " );
      /* 24+64 chars */ s = fd_hex_encode( s, hs->hs.base.client_random, 32UL );
      /* 88+ 1 chars */ s = fd_cstr_append_char( s, ' ' );
      /* 89+64 chars */ s = fd_hex_encode( s, client_secret, 32UL );
      /*   153 chars */     fd_cstr_fini( s );
      keylog_fn( keylog_ctx, buf );
      /*     0 chars */ s = fd_cstr_init( buf );
      /*  0+24 chars */ s = fd_cstr_append_cstr( s, "SERVER_TRAFFIC_SECRET_0 " );
      /* 24+64 chars */ s = fd_hex_encode( s, hs->hs.base.client_random, 32UL );
      /* 88+ 1 chars */ s = fd_cstr_append_char( s, ' ' );
      /* 89+64 chars */ s = fd_hex_encode( s, server_secret, 32UL );
      /*   153 chars */     fd_cstr_fini( s );
      keylog_fn( keylog_ctx, buf );
      break;
    }
  }

}

void
fd_quic_tls_cb_peer_params( void *        context,
                            uchar const * peer_tp_enc,
                            ulong         peer_tp_enc_sz ) {
  fd_quic_conn_t * conn = (fd_quic_conn_t*)context;

  /* decode peer transport parameters */
  fd_quic_transport_params_t peer_tp[1] = {0};
  int rc = fd_quic_decode_transport_params( peer_tp, peer_tp_enc, peer_tp_enc_sz );
  if( FD_UNLIKELY( rc != 0 ) ) {
    FD_DEBUG( FD_LOG_NOTICE(( "fd_quic_decode_transport_params failed" )); )

    /* failed to parse transport params */
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR, __LINE__ );
    return;
  }

  /* flow control parameters */
  conn->tx_max_data                    = peer_tp->initial_max_data;
  conn->tx_initial_max_stream_data_uni = peer_tp->initial_max_stream_data_uni;

  if( !conn->server ) {
    conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni  << 2UL ) + 0x03;
  }

  if( !conn->server ) {
    /* verify retry_src_conn_id */
    uint retry_src_conn_id_sz = conn->retry_src_conn_id.sz;
    if( retry_src_conn_id_sz ) {
      if( FD_UNLIKELY( !peer_tp->retry_source_connection_id_present
                        || peer_tp->retry_source_connection_id_len != retry_src_conn_id_sz
                        || 0 != memcmp( peer_tp->retry_source_connection_id,
                                        conn->retry_src_conn_id.conn_id,
                                        retry_src_conn_id_sz ) ) ) {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR, __LINE__ );
        return;
      }
    } else {
      if( FD_UNLIKELY( peer_tp->retry_source_connection_id_present ) ) {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR, __LINE__ );
        return;
      }
    }
  }

  /* set the max_idle_timeout to the min of our and peer max_idle_timeout */
  conn->idle_timeout = fd_ulong_min( (ulong)(1e6) * peer_tp->max_idle_timeout, conn->idle_timeout );

  conn->transport_params_set = 1;
}

void
fd_quic_tls_cb_handshake_complete( fd_quic_tls_hs_t * hs,
                                   void *             context ) {
  (void)hs;
  fd_quic_conn_t * conn = (fd_quic_conn_t*)context;

  /* need to send quic handshake completion */
  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
    case FD_QUIC_CONN_STATE_DEAD:
      /* ignore */
      return;

    case FD_QUIC_CONN_STATE_HANDSHAKE:
      if( FD_UNLIKELY( !conn->transport_params_set ) ) { /* unreachable */
        FD_LOG_WARNING(( "Handshake marked as completed but transport params are not set. This is a bug!" ));
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR, __LINE__ );
        return;
      }
      conn->handshake_complete = 1;
      conn->state              = FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE;

      if( conn->server ) {
        /* TODO */
        conn->rx_sup_stream_id = ( (ulong)conn->quic->config.initial_rx_max_stream_cnt << 2UL ) + 0x03;
      }

      fd_quic_reschedule_conn( conn, 0 );
      return;

    default:
      FD_LOG_WARNING(( "handshake in unexpected state: %u", conn->state ));
  }
}

static ulong
fd_quic_frame_handle_crypto_frame( void *                   vp_context,
                                   fd_quic_crypto_frame_t * crypto,
                                   uchar const *            p,
                                   ulong                    p_sz ) {
  /* copy the context locally */
  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* determine whether any of the data was already provided */
  fd_quic_conn_t * conn      = context.conn;
  uint             enc_level = context.pkt->enc_level;

  /* offset expected */
  ulong           exp_offset = conn->rx_crypto_offset[enc_level];
  ulong           rcv_offset = crypto->offset;
  ulong           rcv_sz     = crypto->length;

  if( !conn->tls_hs ) {
    /* Handshake already completed. Ignore frame */
    /* TODO consider aborting conn if too many unsoliticted crypto frames arrive */
  } else if( FD_UNLIKELY( rcv_offset > exp_offset ) ) {
    /* if data arrived early, we could buffer, but for now we simply won't ack */
    /* TODO buffer handshake data */
    return FD_QUIC_PARSE_FAIL;
  } else if( FD_UNLIKELY( rcv_offset + rcv_sz <= exp_offset ) ) {
    /* the full range of bytes has already been consumed, so just fall thru */
  } else {
    /* We have bytes that we can use */
    ulong skip = 0;
    if( rcv_offset < exp_offset ) skip = exp_offset - rcv_offset;

    rcv_sz -= skip;
    uchar const * crypto_data = crypto->crypto_data + skip;

    int provide_rc = fd_quic_tls_provide_data( conn->tls_hs,
                                               context.pkt->enc_level,
                                               crypto_data,
                                               rcv_sz );
    if( provide_rc == FD_QUIC_TLS_FAILED ) {
      /* if TLS fails, abort connection */
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_CRYPTO_BUFFER_EXCEEDED, __LINE__ );

      return FD_QUIC_PARSE_FAIL;
    }

    int process_rc = fd_quic_tls_process( conn->tls_hs );
    if( process_rc == FD_QUIC_TLS_FAILED ) {
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_tls_process error at" )); )

      /* if TLS fails, ABORT connection */

      /* if TLS returns an error, we present that as reason:
           FD_QUIC_CONN_REASON_CRYPTO_BASE + tls-alert
         otherwise, send INTERNAL_ERROR */
      uint alert = conn->tls_hs->alert;
      if( alert == 0u ) {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR, __LINE__ );
      } else {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_CRYPTO_BASE + alert, __LINE__ );
      }

      /* don't process any more frames on this connection */
      return FD_QUIC_PARSE_FAIL;
    }

    /* successful, update rx_crypto_offset */
    conn->rx_crypto_offset[enc_level] += rcv_sz;
  }

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  (void)context; (void)p; (void)p_sz;

  /* no "additional" bytes - all already accounted for */
  return FD_QUIC_SUCCESS;
}

void
fd_quic_service( fd_quic_t * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong now = fd_quic_now( quic );

  state->now = now;

  /* service events */
  fd_quic_conn_t * conn = NULL;
  while( service_queue_cnt( state->service_queue ) ) {
    fd_quic_event_t * event = &state->service_queue[0];

    /* copy before removing event */
    conn = event->conn;

    ulong service_time = event->timeout;
    if( now < service_time ) {
      break;
    }

    /* set an initial next_service_time */
    conn->next_service_time = ULONG_MAX;

    /* remove event, later reinserted at new time */
    service_queue_remove_min( state->service_queue );

    /* unset "in service queue" */
    conn->in_service = 0;

    if( FD_UNLIKELY( conn->state == FD_QUIC_CONN_STATE_INVALID ) ) {
      /* connection shouldn't have been scheduled,
         and is now removed, so just continue */
      continue;
    }

    if( FD_UNLIKELY( now > conn->last_activity + ( conn->idle_timeout / 2 ) ) ) {
      if( FD_UNLIKELY( now > conn->last_activity + conn->idle_timeout ) ) {
        if( FD_LIKELY( conn->state != FD_QUIC_CONN_STATE_DEAD ) ) {
          /* rfc9000 10.1 Idle Timeout
             "... the connection is silently closed and its state is discarded
             when it remains idle for longer than the minimum of the
             max_idle_timeout value advertised by both endpoints." */
          FD_DEBUG( FD_LOG_WARNING(( "%s  conn %p  conn_idx: %u  closing due to idle timeout (%g ms)",
              conn->server?"SERVER":"CLIENT",
              (void *)conn, conn->conn_idx, (double)conn->idle_timeout / 1e6 )); )

          conn->state = FD_QUIC_CONN_STATE_DEAD;
          quic->metrics.conn_aborted_cnt++;
        }
      } else if( FD_QUIC_PING_ENABLE ) {
        /* send PING */
        if( !( conn->flags & FD_QUIC_CONN_FLAGS_PING ) ) {
          conn->flags         |= FD_QUIC_CONN_FLAGS_PING;
          conn->flags         &= ~FD_QUIC_CONN_FLAGS_PING_SENT;
          conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;     /* update to be sent in next packet */
        }
      }
    }

    if( FD_UNLIKELY( conn->state == FD_QUIC_CONN_STATE_DEAD ) ) {
      fd_quic_cb_conn_final( quic, conn ); /* inform user before freeing */
      fd_quic_conn_free( quic, conn );
      continue; /* do NOT reschedule freed connection */
    }

    /* state cannot be DEAD here */
    fd_quic_conn_service( quic, conn );

    /* dead? don't reinsert, just clean up */
    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_INVALID:
        /* skip entirely */
        break;

      case FD_QUIC_CONN_STATE_DEAD:
      /* if DEAD here, it's because it transitioned to DEAD during the call to service
         it may also have been rescheduled, so ensure it is rescheduled and allow the
         usual cleanup to occur */

      default:
        /* only schedule if not already scheduled */
        if( !conn->in_service ) {
          fd_quic_schedule_conn( conn );
        }
    }
  }
}

/* attempt to transmit buffered data

   returns 0 if successful, or 1 otherwise */
uint
fd_quic_tx_buffered_raw(
    fd_quic_t *      quic,
    uchar const *    tx,
    ulong            tx_sz,
    uchar const      dst_mac_addr[ static 6 ],
    ushort *         ipv4_id,
    uint             dst_ipv4_addr,
    ushort           src_udp_port,
    ushort           dst_udp_port,
    int              flush
) {

  /* nothing to do */
  if( FD_UNLIKELY( tx_sz==0 ) ) {
    if( flush ) {
      /* send empty batch to flush tx */
      fd_aio_pkt_info_t aio_buf = { .buf = NULL, .buf_sz = 0 };
      int aio_rc = fd_aio_send( &quic->aio_tx, &aio_buf, 0, NULL, 1 );
      (void)aio_rc; /* don't care about result */
    }
    return 0u;
  }

  fd_quic_config_t * config = &quic->config;
  fd_quic_state_t *  state  = fd_quic_get_state( quic );

  uchar * const crypt_scratch = state->crypt_scratch;

  uchar * cur_ptr = state->crypt_scratch;
  ulong   cur_sz  = sizeof( state->crypt_scratch );

  /* TODO much of this may be prepared ahead of time */
  fd_quic_pkt_t pkt;

  memcpy( pkt.eth->dst, dst_mac_addr,                   6 );
  memcpy( pkt.eth->src, quic->config.link.src_mac_addr, 6 );
  pkt.eth->net_type = FD_ETH_HDR_TYPE_IP;

  pkt.ip4->verihl       = FD_IP4_VERIHL(4,5);
  pkt.ip4->tos          = (uchar)(config->net.dscp << 2); /* could make this per-connection or per-stream */
  pkt.ip4->net_tot_len  = (ushort)( 20 + 8 + tx_sz );
  pkt.ip4->net_id       = *ipv4_id++;
  pkt.ip4->net_frag_off = 0x4000u; /* don't fragment */
  pkt.ip4->ttl          = 64; /* TODO make configurable */
  pkt.ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  pkt.ip4->check        = 0;
  pkt.udp->net_sport    = src_udp_port;
  pkt.udp->net_dport    = dst_udp_port;
  pkt.udp->net_len      = (ushort)( 8 + tx_sz );
  pkt.udp->check        = 0x0000;

  /* TODO saddr could be zero -- should use the kernel routing table to
     determine an appropriate source address */

  /* copy to avoid alignment issues */
  memcpy( &pkt.ip4->saddr_c, &config->net.ip_addr, 4 );
  memcpy( &pkt.ip4->daddr_c, &dst_ipv4_addr,       4 );

  /* todo use fd_util Ethernet / IPv4 impl */

  ulong rc = fd_quic_encode_eth( cur_ptr, cur_sz, pkt.eth );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "fd_quic_encode_eth failed with buffer overrun" ));
  }

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_encode_ip4( cur_ptr, cur_sz, pkt.ip4 );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "fd_quic_encode_ip4 failed with buffer overrun" ));
  }

  /* Compute checksum over network byte order header */
  fd_ip4_hdr_t * ip4_encoded = (fd_ip4_hdr_t *)fd_type_pun( cur_ptr );
  ip4_encoded->check = (ushort)fd_ip4_hdr_check_fast( ip4_encoded );

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_encode_udp( cur_ptr, cur_sz, pkt.udp );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "fd_quic_encode_udp failed with buffer overrun" ));
  }

  cur_ptr += rc;
  cur_sz  -= rc;

  /* need enough space for payload and tag */
  if( FD_UNLIKELY( (ulong)tx_sz > cur_sz ) ) {
    FD_LOG_WARNING(( "payload too big for buffer (%lu>%lu)", tx_sz, cur_sz ));
    return FD_QUIC_FAILED;
  }
  fd_memcpy( cur_ptr, tx, tx_sz );

  cur_ptr += tx_sz;
  cur_sz  -= tx_sz;

  fd_aio_pkt_info_t aio_buf = { .buf = crypt_scratch, .buf_sz = (ushort)( cur_ptr - crypt_scratch ) };
  int aio_rc = fd_aio_send( &quic->aio_tx, &aio_buf, 1, NULL, flush );
  if( aio_rc == FD_AIO_ERR_AGAIN ) {
    /* transient condition - try later */
    return FD_QUIC_FAILED;
  } else if( aio_rc != FD_AIO_SUCCESS ) {
    FD_LOG_WARNING(( "Fatal error reported by aio peer" ));
    /* fallthrough to reset buffer */
  }

  quic->metrics.net_tx_pkt_cnt += aio_rc==FD_AIO_SUCCESS;
  if (FD_LIKELY (aio_rc==FD_AIO_SUCCESS) ) {
    quic->metrics.net_tx_byte_cnt += aio_buf.buf_sz;
  }

  return FD_QUIC_SUCCESS; /* success */
}

uint
fd_quic_tx_buffered( fd_quic_t *      quic,
                     fd_quic_conn_t * conn,
                     uchar const *    buf,
                     ulong            sz,
                     int              flush ) {
  fd_quic_endpoint_t *peer = &conn->peer[conn->cur_peer_idx];
  return fd_quic_tx_buffered_raw(
      quic,
      buf,
      sz,
      peer->mac_addr,
      &conn->ipv4_id,
      peer->net.ip_addr,
      conn->host.udp_port,
      peer->net.udp_port,
      flush );
}

struct fd_quic_pkt_hdr {
  union {
    fd_quic_initial_t   initial;
    fd_quic_handshake_t handshake;
    fd_quic_one_rtt_t   one_rtt;
    fd_quic_retry_hdr_t retry;
    /* don't currently support early data */
  } quic_pkt;
  uint enc_level; /* implies the type of quic_pkt */
};
typedef struct fd_quic_pkt_hdr fd_quic_pkt_hdr_t;

/* populate the fd_quic_pkt_hdr_t */
void
fd_quic_pkt_hdr_populate( fd_quic_pkt_hdr_t * pkt_hdr,
                          uint                enc_level,
                          ulong               pkt_number,
                          fd_quic_conn_t *    conn,
                          uchar               key_phase,
                          uint                initial ) {
  pkt_hdr->enc_level = enc_level;

  /* current peer endpoint */
  fd_quic_endpoint_t * peer         = &conn->peer[conn->cur_peer_idx];
  fd_quic_conn_id_t *  peer_conn_id = &peer->conn_id;

  /* our current conn_id */
  ulong conn_id = conn->our_conn_id[conn->cur_conn_id_idx];

  switch( enc_level ) {
    case fd_quic_enc_level_initial_id:
      pkt_hdr->quic_pkt.initial.hdr_form         = 1;
      pkt_hdr->quic_pkt.initial.fixed_bit        = 1;
      pkt_hdr->quic_pkt.initial.long_packet_type = 0;      /* TODO should be set by encoder */
      pkt_hdr->quic_pkt.initial.reserved_bits    = 0;      /* must be set to zero by rfc9000 17.2 */
      pkt_hdr->quic_pkt.initial.pkt_number_len   = 3;      /* indicates 4-byte packet number TODO vary? */
      pkt_hdr->quic_pkt.initial.pkt_num_bits     = 4 * 8;  /* actual number of bits to encode */
      pkt_hdr->quic_pkt.initial.version          = conn->version;
      pkt_hdr->quic_pkt.initial.dst_conn_id_len  = peer_conn_id->sz;
      // .dst_conn_id
      pkt_hdr->quic_pkt.initial.src_conn_id_len  = FD_QUIC_CONN_ID_SZ;
      // .src_conn_id
      // .token - below
      pkt_hdr->quic_pkt.initial.len              = 0;  /* length of payload initially 0 */
      pkt_hdr->quic_pkt.initial.pkt_num          = pkt_number;

      fd_memcpy( pkt_hdr->quic_pkt.initial.dst_conn_id,
              peer_conn_id->conn_id,
              peer_conn_id->sz );
      memcpy( pkt_hdr->quic_pkt.initial.src_conn_id,
              &conn_id,
              FD_QUIC_CONN_ID_SZ );

      /* Initial packets sent by the server MUST set the Token Length field to 0. */
      if ( conn->quic->config.role == FD_QUIC_ROLE_CLIENT && conn->token_len ) {
        pkt_hdr->quic_pkt.initial.token_len       = conn->token_len;
        fd_memcpy( &pkt_hdr->quic_pkt.initial.token, &conn->token, conn->token_len );
      } else {
        pkt_hdr->quic_pkt.initial.token_len       = 0;
      }

      return;

    case fd_quic_enc_level_handshake_id:
      pkt_hdr->quic_pkt.handshake.hdr_form         = 1;
      pkt_hdr->quic_pkt.handshake.fixed_bit        = 1;
      pkt_hdr->quic_pkt.handshake.long_packet_type = 2;
      pkt_hdr->quic_pkt.handshake.reserved_bits    = 0;      /* must be set to zero by rfc9000 17.2 */
      pkt_hdr->quic_pkt.handshake.pkt_number_len   = 3;      /* indicates 4-byte packet number TODO vary? */
      pkt_hdr->quic_pkt.handshake.pkt_num_bits     = 4 * 8;  /* actual number of bits to encode */
      pkt_hdr->quic_pkt.handshake.version          = conn->version;

      /* destination */
      if( initial ) {
        fd_memcpy( pkt_hdr->quic_pkt.initial.dst_conn_id,
                conn->orig_dst_conn_id.conn_id,
                conn->orig_dst_conn_id.sz );
        pkt_hdr->quic_pkt.initial.dst_conn_id_len = conn->orig_dst_conn_id.sz;
      } else {
        fd_memcpy( pkt_hdr->quic_pkt.initial.dst_conn_id,
                peer_conn_id->conn_id,
                peer_conn_id->sz );
        pkt_hdr->quic_pkt.initial.dst_conn_id_len = peer_conn_id->sz;
      }

      /* source */
      FD_STORE( ulong, pkt_hdr->quic_pkt.handshake.src_conn_id, conn_id );
      pkt_hdr->quic_pkt.handshake.src_conn_id_len = sizeof(ulong);

      pkt_hdr->quic_pkt.handshake.len             = 0; /* length of payload initially 0 */
      pkt_hdr->quic_pkt.handshake.pkt_num         = pkt_number;
      break;

    case fd_quic_enc_level_appdata_id:
    {
      /* use 1 bit of rand for spin bit */
      uchar sb = conn->spin_bit;

      /* one_rtt has a short header */
      pkt_hdr->quic_pkt.one_rtt.hdr_form         = 0;
      pkt_hdr->quic_pkt.one_rtt.fixed_bit        = 1;
      pkt_hdr->quic_pkt.one_rtt.spin_bit         = sb;         /* should either match or flip for client/server */
                                                               /* randomized for disabled spin bit */
      pkt_hdr->quic_pkt.one_rtt.reserved0        = 0;          /* must be set to zero by rfc9000 17.2 */
      pkt_hdr->quic_pkt.one_rtt.key_phase        = key_phase;  /* flipped on key change */
      pkt_hdr->quic_pkt.one_rtt.pkt_number_len   = 3;          /* indicates 4-byte packet number TODO vary? */
      pkt_hdr->quic_pkt.one_rtt.pkt_num_bits     = 4 * 8;      /* actual number of bits to encode */

      /* destination */
      fd_memcpy( pkt_hdr->quic_pkt.one_rtt.dst_conn_id,
              peer_conn_id->conn_id,
              peer_conn_id->sz );
      pkt_hdr->quic_pkt.one_rtt.dst_conn_id_len  = peer_conn_id->sz;

      pkt_hdr->quic_pkt.one_rtt.pkt_num          = pkt_number;
      return;
    }

    default:
      FD_LOG_ERR(( "%s - logic error: unexpected enc_level", __func__ ));
  }
}

/* set the payload size within the packet header */
void
fd_quic_pkt_hdr_set_payload_sz( fd_quic_pkt_hdr_t * pkt_hdr, uint enc_level, uint payload_sz ) {
  switch( enc_level ) {
    case fd_quic_enc_level_initial_id:
      pkt_hdr->quic_pkt.initial.len = payload_sz;
      break;

    case fd_quic_enc_level_handshake_id:
      pkt_hdr->quic_pkt.handshake.len = payload_sz;
      break;

    case fd_quic_enc_level_appdata_id:
      /* does not have length - so nothing to do */
      break;

    default:
      FD_LOG_ERR(( "%s - logic error: unexpected enc_level", __func__ ));
  }
}

/* calculate the footprint of the current header */
ulong
fd_quic_pkt_hdr_footprint( fd_quic_pkt_hdr_t * pkt_hdr, uint enc_level ) {
  switch( enc_level ) {
    case fd_quic_enc_level_initial_id:
      return fd_quic_encode_footprint_initial( &pkt_hdr->quic_pkt.initial );
    case fd_quic_enc_level_handshake_id:
      return fd_quic_encode_footprint_handshake( &pkt_hdr->quic_pkt.handshake );
    case fd_quic_enc_level_appdata_id:
      return fd_quic_encode_footprint_one_rtt( &pkt_hdr->quic_pkt.one_rtt );
    default:
      FD_LOG_ERR(( "%s - logic error: unexpected enc_level", __func__ ));
  }
}

/* encode packet header into buffer */
ulong
fd_quic_pkt_hdr_encode( uchar * cur_ptr, ulong cur_sz, fd_quic_pkt_hdr_t * pkt_hdr, uint enc_level ) {
  switch( enc_level ) {
    case fd_quic_enc_level_initial_id:;
      return fd_quic_encode_initial( cur_ptr, cur_sz, &pkt_hdr->quic_pkt.initial );
    case fd_quic_enc_level_handshake_id:
      return fd_quic_encode_handshake( cur_ptr, cur_sz, &pkt_hdr->quic_pkt.handshake );
    case fd_quic_enc_level_appdata_id:
      return fd_quic_encode_one_rtt( cur_ptr, cur_sz, &pkt_hdr->quic_pkt.one_rtt );
    default:
      FD_LOG_ERR(( "%s - logic error: unexpected enc_level", __func__ ));
  }
}

/* returns the packet number length */
uint
fd_quic_pkt_hdr_pkt_number_len( fd_quic_pkt_hdr_t * pkt_hdr,
                                uint            enc_level ) {
  switch( enc_level ) {
    case fd_quic_enc_level_initial_id:   return pkt_hdr->quic_pkt.initial.pkt_number_len + 1u;
    case fd_quic_enc_level_handshake_id: return pkt_hdr->quic_pkt.handshake.pkt_number_len + 1u;
    case fd_quic_enc_level_appdata_id:   return pkt_hdr->quic_pkt.one_rtt.pkt_number_len + 1u;
    default:
      FD_LOG_ERR(( "%s - logic error: unexpected enc_level", __func__ ));
  }
}

static ulong
fd_quic_gen_close_frame( fd_quic_conn_t * conn,
                         uchar *          payload_ptr,
                         uchar *          payload_end ) {

  if( conn->flags & FD_QUIC_CONN_FLAGS_CLOSE_SENT ) return 0UL;
  conn->flags |= FD_QUIC_CONN_FLAGS_CLOSE_SENT;

  ulong frame_sz;
  if( conn->reason != 0u || conn->state == FD_QUIC_CONN_STATE_PEER_CLOSE ) {
    fd_quic_conn_close_0_frame_t conn_close_0 = {
      .error_code           = conn->reason,
      .frame_type           = 0U, /* we do not know the frame in question */
      .reason_phrase_length = 0U  /* no reason phrase */
    };
    frame_sz = fd_quic_encode_conn_close_0_frame( payload_ptr,
                                                  (ulong)( payload_end - payload_ptr ),
                                                  &conn_close_0 );
  } else {
    fd_quic_conn_close_1_frame_t conn_close_1 = {
      .error_code           = conn->app_reason,
      .reason_phrase_length = 0U /* no reason phrase */
    };
    frame_sz = fd_quic_encode_conn_close_1_frame( payload_ptr,
                                                  (ulong)( payload_end - payload_ptr ),
                                                  &conn_close_1 );
  }

  if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) {
    FD_LOG_WARNING(( "fd_quic_encode_conn_close_frame failed, but space should have been available" ));
    return 0UL;
  }

  return frame_sz;
}

static uchar *
fd_quic_gen_handshake_frames( fd_quic_conn_t *     conn,
                              uchar *              payload_ptr,
                              uchar *              payload_end,
                              uint                 enc_level,
                              fd_quic_pkt_meta_t * pkt_meta,
                              ulong                now ) {

  fd_quic_tls_hs_data_t * hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
  if( !hs_data ) return payload_ptr;

  ulong hs_offset   = 0; /* offset within the current hs_data */
  ulong sent_offset = conn->hs_sent_bytes[enc_level];
  ulong ackd_offset = conn->hs_ackd_bytes[enc_level];
  /* offset within stream */
  ulong offset = fd_ulong_max( sent_offset, ackd_offset );

  /* track pkt_meta values */
  ulong offset_lo = offset;
  ulong offset_hi = offset;

  while( hs_data ) {
    /* skip data we've sent */
    if( hs_data->offset + hs_data->data_sz <= offset ) {
      hs_data = fd_quic_tls_get_next_hs_data( conn->tls_hs, hs_data );
      continue;
    }
    if( FD_UNLIKELY( hs_data->offset > offset ) ) {
      /* we have a gap - this shouldn't happen */
      FD_LOG_WARNING(( "gap in TLS handshake data" ));
      /* TODO should probably tear down connection */
      break;
    }

    /* encode hs_data into frame */
    hs_offset = offset - hs_data->offset;

    /* handshake data to send */
    uchar const * cur_data    = hs_data->data    + hs_offset;
    ulong         cur_data_sz = hs_data->data_sz - hs_offset;

    /* build crypto frame */
    fd_quic_crypto_frame_t crypto = {
      .offset      = offset,
      .length      = cur_data_sz,
      .crypto_data = cur_data
    };
    ulong frame_sz = fd_quic_encode_crypto_frame(
        payload_ptr, (ulong)( payload_end - payload_ptr ), &crypto );
    if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) break;
    payload_ptr += frame_sz;

    /* update pkt_meta values */
    offset_hi += cur_data_sz;

    /* move to next hs_data */
    offset     += cur_data_sz;
    conn->hs_sent_bytes[enc_level] += cur_data_sz;

    /* TODO load more hs_data into a crypto frame, if available
        currently tricky, because encode_crypto_frame copies payload */
  }

  /* update packet meta */
  if( offset_hi > offset_lo ) {
    pkt_meta->flags          |= FD_QUIC_PKT_META_FLAGS_HS_DATA;
    pkt_meta->range.offset_lo = offset_lo;
    pkt_meta->range.offset_hi = offset_hi;
    pkt_meta->expiry          = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );
  }

  return payload_ptr;
}

static ulong
fd_quic_gen_handshake_done_frame( fd_quic_conn_t *     conn,
                                  uchar *              payload_ptr,
                                  uchar *              payload_end,
                                  fd_quic_pkt_meta_t * pkt_meta,
                                  ulong                now ) {
  if( !conn->handshake_done_send ) return 0UL;
  conn->handshake_done_send = 0;
  if( FD_UNLIKELY( conn->handshake_done_ackd  ) ) return 0UL;
  if( FD_UNLIKELY( payload_ptr >= payload_end ) ) return 0UL;
  /* send handshake done frame */
  pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_HS_DONE;
  pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );
  payload_ptr[0] = 0x1E;
  return 1UL;
}

static ulong
fd_quic_gen_max_data_frame( fd_quic_conn_t *     conn,
                            uchar *              payload_ptr,
                            uchar *              payload_end,
                            ulong                pkt_number ) {

  if( conn->quic->config.role==FD_QUIC_ROLE_CLIENT ) return 0UL;
  if( !FD_QUIC_MAX_STREAMS_ALWAYS &&
      conn->rx_limit_pktnum != FD_QUIC_PKT_NUM_PENDING ) {
    return 0UL;
  }

  fd_quic_max_data_frame_t max_data = { .max_data = conn->rx_max_data };
  ulong frame_sz = fd_quic_encode_max_data_frame( payload_ptr,
      (ulong)( payload_end - payload_ptr ),
      &max_data );
  if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) return 0UL;

  conn->rx_limit_pktnum = pkt_number;
  conn->upd_pkt_number  = pkt_number;
  return frame_sz;
}

static ulong
fd_quic_gen_max_streams_frame( fd_quic_conn_t *     conn,
                               uchar *              payload_ptr,
                               uchar *              payload_end,
                               ulong                pkt_number ) {

  if( conn->quic->config.role==FD_QUIC_ROLE_CLIENT ) return 0UL;
  if( !FD_QUIC_MAX_STREAMS_ALWAYS &&
      conn->rx_limit_pktnum != FD_QUIC_PKT_NUM_PENDING ) {
    return 0UL;
  }

  /* 0x02 Client-Initiated, Unidirectional
     0x03 Server-Initiated, Unidirectional */
  ulong max_streams_unidir = conn->rx_sup_stream_id >> 2;
  fd_quic_max_streams_frame_t max_streams = {
    .stream_type = 1,
    .max_streams = max_streams_unidir
  };
  ulong frame_sz = fd_quic_encode_max_streams_frame( payload_ptr,
      (ulong)( payload_end - payload_ptr ),
      &max_streams );
  if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) return 0UL;

  conn->rx_limit_pktnum = pkt_number;
  conn->upd_pkt_number  = pkt_number;
  return frame_sz;
}

static ulong
fd_quic_gen_ping_frame( fd_quic_conn_t *     conn,
                        uchar *              payload_ptr,
                        uchar *              payload_end,
                        ulong                pkt_number ) {

  if( ~conn->flags & FD_QUIC_CONN_FLAGS_PING       ) return 0UL;
  if(  conn->flags & FD_QUIC_CONN_FLAGS_PING_SENT  ) return 0UL;

  fd_quic_ping_frame_t ping = {0};
  ulong frame_sz = fd_quic_encode_ping_frame( payload_ptr,
      (ulong)( payload_end - payload_ptr ),
      &ping );
  if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) return 0UL;
  conn->flags |= FD_QUIC_CONN_FLAGS_PING_SENT;

  conn->upd_pkt_number = pkt_number;
  return frame_sz;
}

static uchar *
fd_quic_gen_stream_frames( fd_quic_conn_t *     conn,
                           uchar *              payload_ptr,
                           uchar *              payload_end,
                           fd_quic_pkt_meta_t * pkt_meta,
                           ulong                pkt_number,
                           ulong                now ) {

  fd_quic_state_t *           state        = fd_quic_get_state( conn->quic );
  fd_quic_tx_stream_pool_t *  tx_streams   = state->tx_streams;
  fd_quic_tx_stream_t *       tx_pool      = fd_quic_tx_stream_pool( tx_streams );
  fd_quic_tx_stream_dlist_t * send_streams = conn->send_streams;
  fd_quic_tx_stream_dlist_t * wait_streams = conn->wait_streams;

  while( !fd_quic_tx_stream_dlist_is_empty( send_streams, tx_pool ) &&
         pkt_meta->var_sz < FD_QUIC_PKT_META_VAR_MAX ) {

    fd_quic_tx_stream_t * cur_stream = fd_quic_tx_stream_dlist_ele_peek_head( send_streams, tx_pool );
    ulong const           stream_sz  = cur_stream->data_sz;

    fd_quic_stream_frame_t stream = {
      .stream_id  = cur_stream->stream_id,
      /* optional fields */
      .offset_opt = 0,
      .length_opt = 1, /* always include length */
      .length     = stream_sz,
      .fin_opt    = 1
    };

    /* fragment if out of space
       FIXME: Don't fragment if we have less than ~200 bytes to spare */
    ulong frame_sz = stream_sz + fd_quic_encode_footprint_stream_frame( &stream );
    if( (long)frame_sz > payload_end - payload_ptr ) break;

    /* output */
    frame_sz = fd_quic_encode_stream_frame( payload_ptr,
        (ulong)( payload_end - payload_ptr ),
        &stream );
    if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) {
      FD_LOG_WARNING(( "fd_quic_encode_stream_frame failed, but space should have been available" ));
      break;
    }
    payload_ptr += frame_sz;

    /* copy buffered data to packet */
    fd_memcpy( payload_ptr, cur_stream->data, stream_sz );
    payload_ptr += stream_sz;

    /* packet metadata */
    pkt_meta->flags  |= FD_QUIC_PKT_META_FLAGS_STREAM;
    pkt_meta->expiry  = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

    /* add max_data to pkt_meta->var */
    pkt_meta->var[pkt_meta->var_sz].key =
        FD_QUIC_PKT_META_KEY( FD_QUIC_PKT_META_TYPE_STREAM_DATA, 0, cur_stream->stream_id );
    pkt_meta->var_sz = (uchar)( pkt_meta->var_sz + 1 );
    cur_stream->upd_pkt_number    = pkt_number;

    /* move stream to wait list */
    fd_quic_tx_stream_dlist_ele_pop_head ( send_streams,             tx_pool );
    fd_quic_tx_stream_dlist_ele_push_tail( wait_streams, cur_stream, tx_pool );
  }

  return payload_ptr;
}

uchar *
fd_quic_gen_frames( fd_quic_conn_t *     conn,
                    uchar *              payload_ptr,
                    uchar *              payload_end,
                    uint                 enc_level,
                    fd_quic_pkt_meta_t * pkt_meta,
                    ulong                pkt_number,
                    ulong                now ) {

  uint closing = 0U;
  switch( conn->state ) {
  case FD_QUIC_CONN_STATE_PEER_CLOSE:
  case FD_QUIC_CONN_STATE_ABORT:
  case FD_QUIC_CONN_STATE_CLOSE_PENDING:
    closing = 1u;
  }

  payload_ptr = fd_quic_gen_ack_frames( conn->ack_gen, &conn->quic->config, payload_ptr, payload_end, enc_level, now );
  if( FD_UNLIKELY( closing ) ) {
    payload_ptr += fd_quic_gen_close_frame( conn, payload_ptr, payload_end );
  } else {
    payload_ptr = fd_quic_gen_handshake_frames( conn, payload_ptr, payload_end, enc_level, pkt_meta, now );
    if( enc_level == fd_quic_enc_level_appdata_id ) {
      payload_ptr += fd_quic_gen_handshake_done_frame( conn, payload_ptr, payload_end, pkt_meta, now );
      if( conn->upd_pkt_number >= pkt_number ) {
        payload_ptr += fd_quic_gen_max_data_frame   ( conn, payload_ptr, payload_end, pkt_number );
        payload_ptr += fd_quic_gen_max_streams_frame( conn, payload_ptr, payload_end, pkt_number );
        payload_ptr += fd_quic_gen_ping_frame       ( conn, payload_ptr, payload_end, pkt_number );
      }
      if( FD_LIKELY( conn->hs_data_empty ) ) {
        payload_ptr = fd_quic_gen_stream_frames( conn, payload_ptr, payload_end, pkt_meta, pkt_number, now );
      }
    }
  }

  return payload_ptr;
}

/* transmit
     looks at each of the following dependent on state, and creates
     a packet to transmit:
       acks
       handshake data (tls)
       handshake done
       ping
       stream data */
static void
fd_quic_conn_tx( fd_quic_t *      quic,
                 fd_quic_conn_t * conn ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* used for encoding frames into before encrypting */
  uchar *  crypt_scratch    = state->crypt_scratch;
  ulong    crypt_scratch_sz = sizeof( state->crypt_scratch );

  fd_quic_pkt_hdr_t pkt_hdr = {0};

  uchar udp_buf[ 1500 ];
  ulong udp_sz = 0UL;

  /* choose enc_level to tx at */
  /* this function accepts an argument "acks"
   * We want to minimize the number of packets that carry only acks.
   * fd_quic_tx_enc_level determines whether a packet needs sending,
   * and when encryption level should be used.
   * If "acks" is set to 1 (true), fd_quic_tx_enc_level checks for acks.
   * Otherwise, it does not check for acks
   * We set "acks" only on the first call in this function. All subsequent
   * calls do not set it.
   * This ensures that ack-only packets only occur when nothing else needs
   * to be sent */
  uint enc_level = fd_quic_tx_enc_level( conn, 1 /* acks */ );
  /* RFC 9000 Section 17.2.2.1. Abandoning Initial Packets
     > A client stops both sending and processing Initial packets when
     > it sends its first Handshake packet. */
  if( quic->config.role==FD_QUIC_ROLE_CLIENT && enc_level==fd_quic_enc_level_handshake_id ) {
    fd_quic_abandon_enc_level( conn, fd_quic_enc_level_initial_id );
  }

  /* max packet size
     FIXME use PTMUD */
  ulong tx_max_datagram_sz = fd_ulong_if( enc_level==fd_quic_enc_level_appdata_id, FD_QUIC_MAX_PAYLOAD_SZ, FD_QUIC_INITIAL_PAYLOAD_SZ_MAX );
  tx_max_datagram_sz = fd_ulong_min( tx_max_datagram_sz, sizeof(udp_buf) );

  /* nothing to send? */
  if( enc_level == ~0u                       ) return;
  if( conn->state == FD_QUIC_CONN_STATE_DEAD ) return;

  int key_phase_upd = (int)conn->key_phase_upd;
  int key_phase     = (int)conn->key_phase;
  int key_phase_tx  = (int)key_phase ^ key_phase_upd;

  /* key phase flags to set on every relevant pkt_meta */
  uint key_phase_flags = fd_uint_if( enc_level == fd_quic_enc_level_appdata_id,
                                        ( fd_uint_if( key_phase_upd, FD_QUIC_PKT_META_FLAGS_KEY_UPDATE, 0 ) |
                                          fd_uint_if( key_phase_tx,  FD_QUIC_PKT_META_FLAGS_KEY_PHASE,  0 ) ),
                                        0 );

  /* get time, and set reschedule time for at most the idle timeout */
  ulong now    = fd_quic_get_state( quic )->now;
  ulong schedule = now + conn->idle_timeout - (ulong)50e3;

  fd_quic_pkt_meta_t * pkt_meta = NULL;
  while( enc_level != ~0u ) {
    if( !pkt_meta ) {
      if( FD_UNLIKELY( fd_quic_pkt_meta_list_is_empty( state->pkt_meta_free ) ) ) {
        /* when there is no pkt_meta, it's best to keep processing acks
           until some pkt_meta are returned */
        /* FIXME metrics */
        FD_DEBUG( FD_LOG_DEBUG(( "no pkt_meta available" )); )
        return;
      }
      pkt_meta = fd_quic_pkt_meta_list_ele_pop_head( state->pkt_meta_free, state->pkt_meta_pool );
    } else {
      /* reuse packet number */
      conn->pkt_number[pkt_meta->pn_space] = pkt_meta->pkt_number;
    }

    *pkt_meta = (fd_quic_pkt_meta_t){0};

    /* initialize expiry */
    pkt_meta->expiry = now + conn->idle_timeout - (ulong)50e3;

    /* remaining in datagram */
    ulong datagram_rem = tx_max_datagram_sz - udp_sz;

    /* encode into here */
    uchar * cur_ptr = crypt_scratch;
    ulong   cur_sz  = crypt_scratch_sz;

    /* TODO determine actual datagrams size to use */
    cur_sz = fd_ulong_min( cur_sz, datagram_rem );

    /* determine pn_space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* get next packet number
       we burn this number immediately - quic allows gaps, so this isn't harmful
       even if we end up not sending */
    ulong pkt_number = conn->pkt_number[pn_space]++;

    pkt_meta->pn_space   = (uchar)pn_space;
    pkt_meta->pkt_number = pkt_number;

    /* this is the start of a new quic packet
       cur_ptr points at the next byte to fill with a quic pkt */
    /* currently, cur_ptr just points at the start of crypt_scratch
       each quic packet gets encrypted into tx_buf, and the space in
       crypt_scratch is reused */

    /* are we the client initial packet? */
    ulong hs_data_offset = conn->hs_sent_bytes[enc_level];
    uint initial_pkt = (uint)( hs_data_offset == 0 ) & (uint)( !conn->server ) & (uint)( enc_level == fd_quic_enc_level_initial_id );

    /* populate the quic packet header */
    fd_quic_pkt_hdr_populate( &pkt_hdr, enc_level, pkt_number, conn, (uchar)key_phase_tx, initial_pkt );

    ulong initial_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, enc_level );

    /* if we don't have space for an initial header plus
       16 for sample, 16 for tag and 3 bytes for expansion,
       try tx to free space */
    ulong min_rqd = FD_QUIC_CRYPTO_TAG_SZ + FD_QUIC_CRYPTO_SAMPLE_SZ + 3;
    if( initial_hdr_sz + min_rqd > cur_sz ) {
      /* try to free space */
      fd_quic_tx_buffered( quic, conn, udp_buf, udp_sz, 0 );
      udp_sz = 0UL;
      enc_level = fd_quic_tx_enc_level( conn, 0 /* acks */ );
      continue;
    }

    /* start writing payload, leaving room for header and expansion
       due to varint coding, if the header ends up small, we can pad
       1-3 bytes */
    uchar * payload_ptr = cur_ptr + initial_hdr_sz + 3u;
    ulong   payload_sz  = cur_sz  - initial_hdr_sz - 3u;

    /* write padding bytes here
       conveniently, padding is 0x00 */
    for( ulong j = 0; j < 3; ++j ) {
      cur_ptr[initial_hdr_sz + j] = 0x00u;
    }

    /* payload_end leaves room for TAG */
    uchar * payload_end = payload_ptr + payload_sz - FD_QUIC_CRYPTO_TAG_SZ;

    uchar * const frame_start = payload_ptr;
    payload_ptr = fd_quic_gen_frames( conn, payload_ptr, payload_end, enc_level, pkt_meta, pkt_number, now );
    if( FD_UNLIKELY( payload_ptr < frame_start ) ) FD_LOG_CRIT(( "fd_quic_gen_frames failed" ));

    /* did we add any frames? */
    if( payload_ptr==frame_start ) {
      /* we have data to add, but none was added, presumably due
         so space in the datagram */
      ulong free_bytes = (ulong)( payload_ptr - payload_end );
      /* sanity check */
      if( free_bytes > 64 ) {
        /* we should have been able to fit data into 64 bytes
           so stop trying here */
        break;
      }

      /* try to free space */
      fd_quic_tx_buffered( quic, conn, udp_buf, udp_sz, 0 );
      udp_sz = 0UL;
      enc_level = fd_quic_tx_enc_level( conn, 0 /* acks */ );
      continue;
    }

    /* first initial frame is padded to FD_QUIC_MIN_INITIAL_PKT_SZ
       all short quic packets are padded so 16 bytes of sample are available */
    uint tot_frame_sz = (uint)( payload_ptr - frame_start );
    uint base_pkt_len = (uint)tot_frame_sz + fd_quic_pkt_hdr_pkt_number_len( &pkt_hdr, enc_level ) +
                            FD_QUIC_CRYPTO_TAG_SZ;
    uint padding      = initial_pkt ? FD_QUIC_INITIAL_PAYLOAD_SZ_MIN - base_pkt_len : 0u;

    /* TODO possibly don't need both SAMPLE_SZ and TAG_SZ */
    if( base_pkt_len + padding < ( FD_QUIC_CRYPTO_SAMPLE_SZ + FD_QUIC_CRYPTO_TAG_SZ ) ) {
      padding = FD_QUIC_CRYPTO_SAMPLE_SZ + FD_QUIC_CRYPTO_TAG_SZ - base_pkt_len;
    }

    /* this length includes the packet number length (pkt_number_len+1),
       padding and the final TAG */
    uint quic_pkt_len = base_pkt_len + padding;

    /* set the length on the packet header */
    fd_quic_pkt_hdr_set_payload_sz( &pkt_hdr, enc_level, quic_pkt_len );

    /* calc header size, so we can encode it into the space immediately prior to the
       payload */
    ulong act_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, enc_level );

    /* encode packet header into buffer
       allow `initial_hdr_sz + 3` space for the header... as the payload bytes
       start there */
    cur_ptr += initial_hdr_sz + 3u - act_hdr_sz;
    ulong rc = fd_quic_pkt_hdr_encode( cur_ptr, act_hdr_sz, &pkt_hdr, enc_level );

    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      FD_LOG_WARNING(( "fd_quic_pkt_hdr_encode failed, even though there should have been enough space" ));

      /* reschedule, since some data was unable to be sent */
      fd_quic_reschedule_conn( conn, 0 );

      break;
    }

    /* add padding */
    if( FD_UNLIKELY( padding ) ) {
      fd_memset( payload_ptr, 0, padding );
      payload_ptr += padding;
    }

    /* everything successful up to here
       encrypt into tx_ptr,tx_ptr+tx_sz */

    /* TODO encrypt */
#if FD_QUIC_DISABLE_CRYPTO
    ulong quic_pkt_sz = (ulong)( payload_ptr - cur_ptr );
    fd_memcpy( udp_buf+udp_sz, cur_ptr, quic_pkt_sz );
    memset( udp_buf+udp_sz+quic_pkt_sz, 0, 16 );

    /* update tx_ptr and tx_sz */
    udp_sz += quic_pkt_sz + 16;
    (void)act_hdr_sz;
#else
    ulong   quic_pkt_sz    = (ulong)( payload_ptr - cur_ptr );
    ulong   cipher_text_sz = sizeof(udp_buf) - udp_sz;
    uchar * hdr            = cur_ptr;
    ulong   hdr_sz         = act_hdr_sz;
    uchar * pay            = hdr + hdr_sz;
    ulong   pay_sz         = quic_pkt_sz - hdr_sz;

    int server = conn->server;

    fd_quic_crypto_keys_t * hp_keys  = &conn->keys[enc_level][server];
    fd_quic_crypto_keys_t * pkt_keys = key_phase_upd ? &conn->new_keys[server]
                                                     : &conn->keys[enc_level][server];

    pkt_meta->flags |= key_phase_flags;

    if( FD_UNLIKELY( fd_quic_crypto_encrypt( udp_buf+udp_sz, &cipher_text_sz, hdr, hdr_sz,
          pay, pay_sz, pkt_keys, hp_keys, pkt_number ) != FD_QUIC_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_quic_crypto_encrypt failed" ));

      /* reschedule, since some data was unable to be sent */
      fd_quic_reschedule_conn( conn, 0 );

      /* this situation is unlikely to improve, so kill the connection */
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      break;
    }

    udp_sz += cipher_text_sz;
#endif

    /* update packet metadata with summary info */
    pkt_meta->pkt_number = pkt_number;
    pkt_meta->pn_space   = (uchar)pn_space;
    pkt_meta->enc_level  = (uchar)enc_level;

    /* did we send handshake-done? */
    if( pkt_meta->flags & FD_QUIC_PKT_META_FLAGS_HS_DONE ) {
      conn->handshake_done_send = 0;
    }

    if( pkt_meta->flags ) {
      /* add to sent list */
      fd_quic_pkt_meta_list_ele_push_tail( &conn->sent_pkt_meta[enc_level], pkt_meta, state->pkt_meta_pool );
      if( FD_UNLIKELY( fd_quic_pkt_meta_list_ele_peek_head( state->pkt_meta_free, state->pkt_meta_pool ) == pkt_meta ) ) {
        FD_LOG_CRIT(( "circ" ));
      }

      /* update rescheduling variable */
      schedule = fd_ulong_min( schedule, pkt_meta->expiry );
    } else {
      /* free unused meta */
      fd_quic_pkt_meta_list_ele_push_head( state->pkt_meta_free, pkt_meta, state->pkt_meta_pool );
    }

    /* clear pkt_meta for next loop */
    pkt_meta = NULL;

    if( enc_level == fd_quic_enc_level_appdata_id ) {
      /* short header must be last in datagram
         so send in packet immediately */
      fd_quic_tx_buffered( quic, conn, udp_buf, udp_sz, 0 );
      udp_sz = 0UL;
      enc_level = fd_quic_tx_enc_level( conn, 0 /* acks */ );
      /* TODO count here */
      continue;
    }

    /* choose enc_level to tx at */
    enc_level = fd_quic_tx_enc_level( conn, 0 /* acks */ );
  }
  if( pkt_meta ) {
    /* return unused pkt meta */
    conn->pkt_number[pkt_meta->pn_space] = pkt_meta->pkt_number;
    fd_quic_pkt_meta_list_ele_push_head( state->pkt_meta_free, pkt_meta, state->pkt_meta_pool );
    pkt_meta = NULL;
  }

  /* try to send? */
  fd_quic_tx_buffered( quic, conn, udp_buf, udp_sz, 1 );
  udp_sz = 0UL;

  /* reschedule based on expiry */
  fd_quic_reschedule_conn( conn, schedule );
}

void
fd_quic_conn_service( fd_quic_t *      quic,
                      fd_quic_conn_t * conn ) {
  FD_DEBUG( FD_LOG_DEBUG(( "conn=%p service", (void *)conn )); )

  /* handle expiry on pkt_meta */
  fd_quic_pkt_meta_retry( quic, conn, 0 /* don't force */, ~0u /* enc_level */ );

  /* check state
       need reset?
       need close?
       need acks?
       replies?
       data to send?
       dead */
  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_HANDSHAKE:
    case FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE:
      {
        if( conn->tls_hs ) {
          /* call process on TLS */
          int process_rc = fd_quic_tls_process( conn->tls_hs );
          if( process_rc == FD_QUIC_TLS_FAILED ) {
            /* mark as DEAD, and allow it to be cleaned up */
            conn->state = FD_QUIC_CONN_STATE_DEAD;
            fd_quic_reschedule_conn( conn, 0 );
            quic->metrics.conn_aborted_cnt++;
            quic->metrics.conn_err_tls_fail_cnt++;
            return;
          }

          /* if we're the server, we send "handshake-done" frame */
          if( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE && conn->server ) {
            conn->handshake_done_send = 1;

            /* move straight to ACTIVE */
            conn->state = FD_QUIC_CONN_STATE_ACTIVE;

            /* RFC 9001 4.9.2. Discarding Handshake Keys
               > An endpoint MUST discard its Handshake keys when the
               > TLS handshake is confirmed
               RFC 9001 4.1.2. Handshake Confirmed
               > [...] the TLS handshake is considered confirmed at the
               > server when the handshake completes */
            fd_quic_abandon_enc_level( conn, fd_quic_enc_level_handshake_id );

            /* user callback */
            fd_quic_cb_conn_new( quic, conn );

            /* clear out hs_data here, as we don't need it anymore */
            fd_quic_tls_hs_data_t * hs_data = NULL;

            uint enc_level = (uint)fd_quic_enc_level_appdata_id;
            hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
            while( hs_data ) {
              fd_quic_tls_pop_hs_data( conn->tls_hs, enc_level );
              hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
            }

            /* FIXME: HACKY */
            conn->rx_max_data      = 1UL<<61;
            conn->rx_sup_stream_id = 1UL<<61;
            conn->rx_limit_pktnum  = FD_QUIC_PKT_NUM_PENDING;
          }

          /* if we're the client, fd_quic_conn_tx will flush the hs
             buffer so we can receive the HANDSHAKE_DONE frame, and
             transition from CONN_STATE HANDSHAKE_COMPLETE to ACTIVE. */
        }

        /* do we have data to transmit? */
        fd_quic_conn_tx( quic, conn );

        break;
      }

    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
    case FD_QUIC_CONN_STATE_PEER_CLOSE:
        /* user requested close, and may have set a reason code */
        /* transmit the failure reason */
        fd_quic_conn_tx( quic, conn );

        /* schedule another fd_quic_conn_service to free the conn */
        conn->state = FD_QUIC_CONN_STATE_DEAD; /* TODO need draining state wait for 3 * TPO */
        quic->metrics.conn_closed_cnt++;
        fd_quic_reschedule_conn( conn, 0 );

        break;

    case FD_QUIC_CONN_STATE_ABORT:
        /* transmit the failure reason */
        fd_quic_conn_tx( quic, conn );

        /* schedule another fd_quic_conn_service to free the conn */
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        quic->metrics.conn_aborted_cnt++;
        fd_quic_reschedule_conn( conn, 0 );

        break;

    case FD_QUIC_CONN_STATE_ACTIVE:
        /* do we have data to transmit? */
        fd_quic_conn_tx( quic, conn );

        break;

    case FD_QUIC_CONN_STATE_DEAD:
    case FD_QUIC_CONN_STATE_INVALID:
      /* fall thru */
    default:
      return;
  }

  /* check routing and arp for this connection */

}

void
fd_quic_conn_free( fd_quic_t *      quic,
                   fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !conn ) ) {
    FD_LOG_WARNING(( "NULL conn" ));
    return;
  }
  if( FD_UNLIKELY( conn->state == FD_QUIC_CONN_STATE_INVALID ) ) {
    FD_LOG_CRIT(( "double free detected" ));
    return;
  }

  conn->state = FD_QUIC_CONN_STATE_INVALID;

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* remove connection ids from conn_map */

  /* loop over connection ids, and remove each */
  for( ulong j=0; j<conn->our_conn_id_cnt; ++j ) {
    fd_quic_conn_map_t * entry = fd_quic_conn_map_query( state->conn_map, conn->our_conn_id[j], NULL );
    if( FD_LIKELY( entry ) ) fd_quic_conn_map_remove( state->conn_map, entry );
  }

  /* no need to remove this connection from the events queue
     free is called from two places:
       fini    - service will never be called again. All events are destroyed
       service - removes event before calling free. Event only allowed to be
       enqueued once */

  /* free all outgoing streams */
  if( state->tx_streams ) {
    fd_quic_tx_stream_free_all( state->tx_streams, conn );
  }

  /* destroy keys */
  fd_memset( conn->keys, 0, sizeof(conn->keys) );

  /* free tls-hs */
  fd_quic_tls_hs_delete( conn->tls_hs );
  conn->tls_hs = NULL;

  /* put connection back in free list */
  fd_quic_conn_pool_ele_release( state->conns, conn );
  conn->state = FD_QUIC_CONN_STATE_INVALID;

  /* free pkt_metas */
  for( uint j=0; j<4; j++ ) {
    fd_quic_pkt_meta_list_merge_head( state->pkt_meta_free, conn->sent_pkt_meta+j, state->pkt_meta_pool );
  }

  quic->metrics.conn_active_cnt--;

  /* clear keys */
  for( ulong j = 0U; j < 4U; ++j ) {
    for( ulong k = 0U; k < 2U; ++k ) {
      fd_memset( conn->keys[j][k].pkt_key, 0x42, sizeof( conn->keys[0][0].pkt_key ) );
      fd_memset( conn->keys[j][k].hp_key,  0x43, sizeof( conn->keys[0][0].hp_key  ) );
      fd_memset( conn->keys[j][k].iv,      0x45, sizeof( conn->keys[0][0].iv      ) );
    }
  }
  for( ulong k = 0U; k < 2U; ++k ) {
    fd_memset( conn->new_keys[k].pkt_key, 0x42, sizeof( conn->new_keys[0].pkt_key ) );
    fd_memset( conn->new_keys[k].hp_key,  0x43, sizeof( conn->new_keys[0].hp_key  ) );
    fd_memset( conn->new_keys[k].iv,      0x45, sizeof( conn->new_keys[0].iv      ) );
  }
}

fd_quic_conn_t *
fd_quic_connect( fd_quic_t *  quic,
                 uint         dst_ip_addr,
                 ushort       dst_udp_port,
                 char const * sni ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );
  state->now = fd_quic_now( quic );

  fd_rng_t * rng = state->_rng;

  /* create conn ids for us and them
     client creates connection id for the peer, peer immediately replaces it */
  ulong our_conn_id_u64 = fd_rng_ulong( rng );
  fd_quic_conn_id_t peer_conn_id;  fd_quic_conn_id_rand( &peer_conn_id, rng );

  fd_quic_conn_t * conn = fd_quic_conn_create(
      quic,
      our_conn_id_u64,
      &peer_conn_id,
      dst_ip_addr,
      dst_udp_port,
      0, /* client */
      1u /* version */ );

  if( FD_UNLIKELY( !conn ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_conn_create failed" )) );
    return NULL;
  }

  /* choose a port from ephemeral range */
  fd_quic_config_t * config     = &quic->config;
  ushort             ephem_lo   = config->net.ephem_udp_port.lo;
  ushort             ephem_hi   = config->net.ephem_udp_port.hi;
  ushort             next_ephem = state->next_ephem_udp_port;
  ushort             src_port   = next_ephem;
  next_ephem++;
  next_ephem = fd_ushort_if( next_ephem >= ephem_hi, ephem_lo, next_ephem );
  state->next_ephem_udp_port = next_ephem;

  conn->host.udp_port = src_port;

  /* save original destination connection id */

  fd_memcpy( conn->orig_dst_conn_id.conn_id, &peer_conn_id.conn_id, peer_conn_id.sz );
  conn->orig_dst_conn_id.sz = peer_conn_id.sz;

  /* Prepare QUIC-TLS transport params object (sent as a TLS extension).
      Take template from state and mutate certain params in-place.

      See RFC 9000 Section 18 */

  fd_quic_transport_params_t tp[1] = { state->transport_params };

  /* The original_destination_connection_id is omitted by clients.
     Since this is a mutable field, explicitly clear it here. */

  tp->original_destination_connection_id_present = 0;
  tp->original_destination_connection_id_len     = 0;

  /* Similarly, explicitly zero out retry fields. */
  tp->retry_source_connection_id_present     = 0;
  tp->retry_source_connection_id_len     = 0;

  /* Repeat source conn ID -- rationale see fd_quic_handle_v1_initial */

  memcpy( tp->initial_source_connection_id,
          conn->initial_source_conn_id.conn_id,
          FD_QUIC_MAX_CONN_ID_SZ );
  tp->initial_source_connection_id_present = 1;
  tp->initial_source_connection_id_len     = FD_QUIC_CONN_ID_SZ;

  /* validate transport parameters */

  if( !fd_quic_transport_params_validate( tp ) ) {
    FD_LOG_WARNING(( "fd_quic_transport_params_validate failed" ));
    goto fail_conn;
  }

  /* Create a TLS handshake */

  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
      state->tls,
      (void*)conn,
      0 /*is_server*/,
      sni,
      tp );
  if( FD_UNLIKELY( !tls_hs ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_tls_hs_new failed" )) );
    goto fail_conn;
  }

  /* run process tls immediately */
  int process_rc = fd_quic_tls_process( tls_hs );
  if( FD_UNLIKELY( process_rc == FD_QUIC_TLS_FAILED ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_tls_process error at: %s %d", __FILE__, __LINE__ )) );

    /* We haven't sent any data to the peer yet,
       so simply clean up and fail */
    goto fail_tls_hs;
  }

  conn->tls_hs = tls_hs;

  fd_quic_gen_initial_secret_and_keys( conn, &peer_conn_id );

  fd_quic_reschedule_conn( conn, 0 );

  /* set "called_conn_new" to indicate we should call conn_final
     upon teardown */
  conn->called_conn_new = 1;

  /* everything initialized */
  return conn;

fail_tls_hs:
  /* shut down tls_hs */
  fd_quic_tls_hs_delete( tls_hs );

fail_conn:
  conn->state  = FD_QUIC_CONN_STATE_DEAD;

  return NULL;
}

fd_quic_conn_t *
fd_quic_conn_create( fd_quic_t *               quic,
                     ulong                     our_conn_id,
                     fd_quic_conn_id_t const * peer_conn_id,
                     uint                      dst_ip_addr,
                     ushort                    dst_udp_port,
                     int                       server,
                     uint                      version ) {

  fd_quic_config_t * config = &quic->config;
  fd_quic_state_t *  state  = fd_quic_get_state( quic );

  /* fetch top of connection free list */
  if( FD_UNLIKELY( !fd_quic_conn_pool_free( state->conns ) ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_conn_create failed: no free conn slots" )) );
    quic->metrics.conn_err_no_slots_cnt++;
    return NULL;
  }

  if( FD_UNLIKELY( fd_quic_pkt_meta_list_is_empty( state->pkt_meta_free ) ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_conn_create failed: no free pkt meta" )) );
    return NULL;
  }

  /* insert into connection map */
  fd_quic_conn_map_t * insert_entry = fd_quic_conn_map_insert( state->conn_map, our_conn_id );
  /* if insert failed (should be impossible) fail, and do not remove connection
     from free list */
  if( FD_UNLIKELY( insert_entry == NULL ) ) {
    FD_LOG_WARNING(( "fd_quic_conn_create failed: failed to register new conn ID" ));
    return NULL;
  }

  /* remove from free list */
  uint             conn_idx = (uint)fd_quic_conn_pool_idx_acquire( state->conns );
  fd_quic_conn_t * conn     = state->conns + conn_idx;
  memset( conn, 0, sizeof(fd_quic_conn_t) );
  conn->quic = quic;
  fd_quic_tx_stream_treap_new( conn->tx_streams, quic->limits.tx_stream_cnt );
  fd_quic_tx_stream_dlist_new( conn->send_streams );
  fd_quic_tx_stream_dlist_new( conn->wait_streams );
  for( uint j=0U; j<FD_QUIC_NUM_ENC_LEVELS; j++ ) {
    fd_quic_pkt_meta_list_new( conn->sent_pkt_meta + j );
  }

  /* set connection map insert_entry to new connection */
  insert_entry->conn_idx = conn_idx;

  conn->next_service_time   = state->now;
  conn->sched_service_time  = ~0UL;

  /* initialize connection members */
  conn->quic                = quic;
  conn->server              = !!server;
  conn->established         = 0;
  conn->version             = version;
  conn->called_conn_new     = 0;
  conn->host                = (fd_quic_net_endpoint_t){
    .ip_addr  = config->net.ip_addr,
    .udp_port = fd_ushort_if( server,
                              config->net.listen_udp_port,
                              state->next_ephem_udp_port )
  };
  fd_memset( &conn->peer[0], 0, sizeof( conn->peer ) );
  conn->local_conn_id       = 0; /* TODO probably set it here, or is it only valid for servers? */
  conn->peer_cnt            = 0;
  conn->our_conn_id_cnt     = 0; /* set later */
  conn->cur_conn_id_idx     = 0;
  conn->cur_peer_idx        = 0;
  conn->token_len           = 0;

  /* start with smallest value we allow, then allow peer to increase */
  conn->handshake_complete  = 0;
  conn->handshake_done_send = 0;
  conn->handshake_done_ackd = 0;
  conn->hs_data_empty       = 0;
  conn->tls_hs              = NULL; /* created later */

  /* initialize stream_id members */
  conn->rx_sup_stream_id      = FD_QUIC_STREAM_TYPE_UNI_CLIENT;
  conn->tx_sup_stream_id      = FD_QUIC_STREAM_TYPE_UNI_CLIENT;
  conn->tx_next_stream_id     = FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  conn->keys_avail = fd_uint_set_bit( 0U, fd_quic_enc_level_initial_id );

  /* rfc9000: s12.3:
     Packet numbers in each packet space start at 0.
     Subsequent packets sent in the same packet number space
       MUST increase the packet number by at least 1
     rfc9002: s3
     It is permitted for some packet numbers to never be used, leaving intentional gaps. */
  fd_memset( conn->exp_pkt_number, 0, sizeof( conn->exp_pkt_number ) );
  fd_memset( conn->last_pkt_number, 0, sizeof( conn->last_pkt_number ) );
  fd_memset( conn->pkt_number, 0, sizeof( conn->pkt_number ) );

  /* crypto offset for first packet always starts at 0 */
  fd_memset( conn->rx_crypto_offset, 0, sizeof( conn->rx_crypto_offset ) );

  /* TODO lots of fd_memset calls that should really be builtin memset */
  fd_memset( conn->hs_sent_bytes, 0, sizeof( conn->hs_sent_bytes ) );
  fd_memset( conn->hs_ackd_bytes, 0, sizeof( conn->hs_ackd_bytes ) );

  fd_memset( &conn->secrets, 0, sizeof( conn->secrets ) );
  fd_memset( &conn->keys, 0, sizeof( conn->keys ) );
  fd_memset( &conn->new_keys, 0, sizeof( conn->new_keys ) );
  /* suites initialized above */

  conn->key_phase            = 0;
  conn->key_phase_upd        = 0;

  conn->state                = FD_QUIC_CONN_STATE_HANDSHAKE;
  conn->reason               = 0;
  conn->app_reason           = 0;
  conn->int_reason           = 0;
  conn->flags                = 0;
  conn->spin_bit             = 0;
  conn->upd_pkt_number       = 0;

  /* initialize connection members */
  ulong our_conn_id_idx = 0;
  conn->our_conn_id[our_conn_id_idx] = our_conn_id;
  conn->our_conn_id_cnt++;

  /* initial source connection id */
  conn->initial_source_conn_id = fd_quic_conn_id_new( &our_conn_id, FD_QUIC_CONN_ID_SZ );

  /* peer connection id */
  ulong peer_idx = 0;
  conn->peer[ peer_idx ].conn_id      = *peer_conn_id;
  conn->peer[ peer_idx ].net.ip_addr  = dst_ip_addr;
  conn->peer[ peer_idx ].net.udp_port = dst_udp_port;
  memset( &conn->peer[ peer_idx ].mac_addr, 0, 6 );
  conn->peer_cnt                      = 1;

  /* flow control params */
  conn->rx_max_data = 0; /* this is what we advertise initially */
  conn->tx_max_data = 0;
  conn->rx_limit_pktnum = FD_QUIC_PKT_NUM_UNUSED;

  /* no stream bytes sent or received yet */
  conn->tx_tot_data = 0;

  /* initial rtt */
  conn->rtt = (ulong)500e6;

  /* highest peer encryption level */
  conn->peer_enc_level = 0;

  /* idle timeout */
  conn->idle_timeout  = config->idle_timeout;
  conn->last_activity = fd_quic_now( quic );

  fd_memset( conn->exp_pkt_number,  0, sizeof( conn->exp_pkt_number  ) );
  fd_memset( conn->last_pkt_number, 0, sizeof( conn->last_pkt_number ) );

  /* transport params */
  fd_quic_transport_params_t * our_tp  = &state->transport_params;
  conn->rx_max_data                    = our_tp->initial_max_data;

  /* update metrics */
  quic->metrics.conn_active_cnt++;
  quic->metrics.conn_created_cnt++;

  /* immediately schedule it */
  fd_quic_schedule_conn( conn );

  /* return connection */
  return conn;
}

ulong
fd_quic_get_next_wakeup( fd_quic_t * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong t = ~(ulong)0;
  if( service_queue_cnt( state->service_queue ) ) {
    t = state->service_queue[0].timeout;
  }

  return t;
}

/* frame handling function default definitions */
static ulong
fd_quic_frame_handle_padding_frame(
    void * context,
    fd_quic_padding_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return 0;
}

static ulong
fd_quic_frame_handle_ping_frame(
    void *                 vp_context,
    fd_quic_ping_frame_t * data,
    uchar const *          p,
    ulong                 p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;
  (void)vp_context;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;
  context.pkt->ping = 1;

  return 0;
}

/* Retry packet metadata
   This will force pkt_meta to be returned to the free list
   for use. It does so by finding unack'ed packet metadata
   and setting the data up for retransmission.
   Set force to 1 to force pkt_meta to be reclaimed even if
   the ack timer hasn't expired. This is used when pkt_meta
   is required immediately and none is available */
void
fd_quic_pkt_meta_retry( fd_quic_t *      quic,
                        fd_quic_conn_t * conn,
                        int              force,
                        uint             arg_enc_level ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong now = fd_quic_get_state( quic )->now;

  /* minimum pkt_meta required to be freed
     If not forcing, 0 is applicable
     Otherwise, we should allow for a normal packet, which
     will likely consist of the following:
       1 ack
       1 max streams
       1 max data
       1 stream data */
  ulong min_freed = force ? 4U : 0U;

  /* count of freed pkt_meta */
  ulong cnt_freed = 0u;

  /* obtain pointer to pkt_meta pool */
  fd_quic_pkt_meta_t *      pool = state->pkt_meta_pool;
  fd_quic_pkt_meta_list_t * free = state->pkt_meta_free;

  while(1) {
    /* find earliest sent pkt_meta over all of the enc_levels */
    uint  enc_level      = arg_enc_level;
    uint  peer_enc_level = conn->peer_enc_level;
    ulong expiry         = ~0ul;
    if( enc_level == ~0u ) {
      for( uint j=0u; j<4u; j++ ) {
        /* TODO this only checks the head of each enc_level
           assuming that pkt_meta is in time order. It IS
           is time order, but not expiry time. */
        if( fd_quic_pkt_meta_list_is_empty( conn->sent_pkt_meta+j ) ) continue;
        fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_list_ele_peek_head( conn->sent_pkt_meta+j, pool );
        if( enc_level == ~0u || pkt_meta->expiry < expiry ) {
          enc_level = j;
          expiry    = pkt_meta->expiry;
        }
      }
      if( FD_UNLIKELY( enc_level == ~0u ) ) return;
    }

    fd_quic_pkt_meta_list_t * sent_list = &conn->sent_pkt_meta[enc_level];
    if( fd_quic_pkt_meta_list_is_empty( sent_list ) ) return;
    fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_list_ele_peek_head( sent_list, pool );
    expiry = pkt_meta->expiry;

    if( force ) {
      /* we're forcing, quit when we've freed enough */
      if( cnt_freed >= min_freed ) return;
    } else {
      /* not forcing, so quit if nothing has expired */
      if( expiry > now ) {
        return;
      }
    }

    /* already moved to another enc_level */
    if( enc_level < peer_enc_level ) {
      /* free pkt_meta */

      /* treat the original packet as-if it were ack'ed */
      fd_quic_reclaim_pkt_meta( conn, pkt_meta, enc_level );
      if( FD_UNLIKELY( fd_quic_pkt_meta_list_is_empty( sent_list ) ) ) FD_LOG_CRIT(( "pkt_meta disappeared" ));
      if( FD_UNLIKELY( fd_quic_pkt_meta_list_ele_pop_head( sent_list, pool )!=pkt_meta ) ) FD_LOG_CRIT(( "pkt_meta is not head" ));
      fd_quic_pkt_meta_list_ele_push_head( free, pkt_meta, pool );

      cnt_freed++;
      continue;
    }

    FD_DEBUG( FD_LOG_DEBUG(( "Retrying enc=%u pkt_num=%lu", pkt_meta->enc_level, pkt_meta->pkt_number )) );

    /* set the data to retry */
    uint flags = pkt_meta->flags;
    if( flags & FD_QUIC_PKT_META_FLAGS_HS_DATA            ) {
      /* find handshake data to retry */
      /* reset offset to beginning of retried range if necessary */
      ulong offset = fd_ulong_max( conn->hs_ackd_bytes[enc_level], pkt_meta->range.offset_lo );
      if( offset < conn->hs_sent_bytes[enc_level] ) {
        conn->hs_sent_bytes[enc_level] = offset;
        conn->upd_pkt_number           = FD_QUIC_PKT_NUM_PENDING;
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
      /* iterate thru the variable section of the pkt_meta
       * and set the max_stream_data to resend for each
       * appropriate entry */
      ulong var_sz = pkt_meta->var_sz;

      /* probably we should consolidate these loops over pkt_meta->var[j] */
      for( ulong j = 0UL; j < var_sz; ++j ) {
        if( pkt_meta->var[j].key.type == FD_QUIC_PKT_META_TYPE_STREAM_DATA ) {
          ulong stream_id = FD_QUIC_PKT_META_STREAM_ID( pkt_meta->var[j].key );
          fd_quic_tx_stream_t * tx_pool = fd_quic_tx_stream_pool( state->tx_streams );
          fd_quic_tx_stream_t * stream  = fd_quic_tx_stream_treap_ele_query( conn->tx_streams, stream_id, tx_pool );
          if( FD_UNLIKELY( !stream ) ) {
            FD_LOG_WARNING(( "Detected ACK timeout for unknown stream. This is a bug" ));
          } else {
            /* Resend entire stream */
            fd_quic_tx_stream_dlist_ele_remove   ( conn->wait_streams, stream, tx_pool );
            fd_quic_tx_stream_dlist_ele_push_head( conn->send_streams, stream, tx_pool );
          }
        }
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_HS_DONE            ) {
      /* do we need to resend the handshake done flag?
         only send if it hasn't already been acked */
      if( FD_LIKELY( !conn->handshake_done_ackd ) ) {
        conn->handshake_done_send = 1;
        conn->upd_pkt_number      = FD_QUIC_PKT_NUM_PENDING;
      }
    }
    if( pkt_meta->pkt_number == conn->rx_limit_pktnum ) {
      /* quota update got lost, retransmit */
      conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    }

    /* free pkt_meta */
    if( FD_UNLIKELY( fd_quic_pkt_meta_list_is_empty( sent_list ) ) ) FD_LOG_CRIT(( "pkt_meta disappeared" ));
    if( FD_UNLIKELY( fd_quic_pkt_meta_list_ele_pop_head( sent_list, pool )!=pkt_meta ) ) FD_LOG_CRIT(( "pkt_meta is not head" ));
    fd_quic_pkt_meta_list_ele_push_head( state->pkt_meta_free, pkt_meta, pool );

    /* reschedule to ensure the data gets processed */
    fd_quic_reschedule_conn( conn, 0 );

    cnt_freed++;
  }
}

/* reclaim resources associated with packet metadata
   this is called in response to received acks */
void
fd_quic_reclaim_pkt_meta( fd_quic_conn_t *     conn,
                          fd_quic_pkt_meta_t * pkt_meta,
                          uint                 enc_level ) {
  fd_quic_state_t * state = fd_quic_get_state( conn->quic );

  uint            flags = pkt_meta->flags;
  fd_quic_range_t range = pkt_meta->range;

  if( FD_UNLIKELY( flags & FD_QUIC_PKT_META_FLAGS_KEY_UPDATE ) ) {
    /* what key phase was used for packet? */
    uint pkt_meta_key_phase = !!( flags & FD_QUIC_PKT_META_FLAGS_KEY_PHASE );

    if( pkt_meta_key_phase != conn->key_phase ) {
      /* key update was acknowledged
         replace with new ones */

      /* TODO improve this code */
#     define COPY_KEY(SERVER,KEY)                         \
        fd_memcpy( &conn->keys[enc_level][SERVER].KEY[0], \
                   &conn->new_keys[SERVER].KEY[0],        \
                   sizeof( conn->keys[enc_level][0].KEY ) )
      COPY_KEY(0,pkt_key);
      COPY_KEY(0,iv);
      COPY_KEY(1,pkt_key);
      COPY_KEY(1,iv);
#     undef COPY_KEY

      /* finally zero out new_keys */
      fd_memset( &conn->new_keys[0], 0, sizeof( fd_quic_crypto_keys_t ) );
      fd_memset( &conn->new_keys[1], 0, sizeof( fd_quic_crypto_keys_t ) );

      /* copy secrets */
      fd_memcpy( &conn->secrets.secret[enc_level][0][0],
                 &conn->secrets.new_secret[0][0],
                 sizeof( conn->secrets.new_secret[0] ) );
      fd_memcpy( &conn->secrets.secret[enc_level][1][0],
                 &conn->secrets.new_secret[1][0],
                 sizeof( conn->secrets.new_secret[1] ) );

      /* zero out new_secret */
      fd_memset( &conn->secrets.new_secret[0][0], 0, sizeof( conn->secrets.new_secret[0] ) );
      fd_memset( &conn->secrets.new_secret[1][0], 0, sizeof( conn->secrets.new_secret[1] ) );

      conn->key_phase     = pkt_meta_key_phase; /* switch to new key phase */
      conn->key_phase_upd = 0;                  /* no longer updating */

      FD_DEBUG( FD_LOG_DEBUG(( "key update completed" )); )

      /* TODO still need to add code to initiate key update */
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_HS_DATA ) {
    /* Note that tls_hs could already be freed */
    /* is this ack'ing the next consecutive bytes?
       if so, we can increase the ack'd bytes
       if not, we retransmit the bytes expected to be ack'd
         we assume a gap means a dropped packet, and
         this policy allows us to free up the pkt_meta here */
    ulong hs_ackd_bytes = conn->hs_ackd_bytes[enc_level];
    if( range.offset_lo <= hs_ackd_bytes ) {
      hs_ackd_bytes = conn->hs_ackd_bytes[enc_level]
                    = fd_ulong_max( hs_ackd_bytes, range.offset_hi );

      /* remove any unused hs_data */
      fd_quic_tls_hs_data_t * hs_data = NULL;

      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
      while( hs_data && hs_data->offset + hs_data->data_sz <= hs_ackd_bytes ) {
        fd_quic_tls_pop_hs_data( conn->tls_hs, enc_level );
        hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
      }
    } else {
      conn->hs_sent_bytes[enc_level] =
          fd_ulong_min( conn->hs_sent_bytes[enc_level], hs_ackd_bytes );
      conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_HS_DONE ) {
    fd_quic_tls_hs_data_t * hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
    while( hs_data ) {
      fd_quic_tls_pop_hs_data( conn->tls_hs, enc_level );
      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, enc_level );
    }

    conn->handshake_done_ackd = 1;
    conn->handshake_done_send = 0;
    conn->hs_data_empty       = 1;

    fd_quic_tls_hs_delete( conn->tls_hs );
    conn->tls_hs = NULL;
  }

  if( pkt_meta->pkt_number == conn->rx_limit_pktnum ) {
    /* local and peer quotas are in sync */
    conn->rx_limit_pktnum = FD_QUIC_PKT_NUM_UNUSED;
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
    /* iterate thru the variable section of the pkt_meta
     * and set the max_stream_data to resend for each
     * appropriate entry */
    ulong var_sz = pkt_meta->var_sz;

    /* probably we should consolidate these loops over pkt_meta->var[j] */
    for( ulong j=0UL; j<var_sz; j++ ) {
      if( pkt_meta->var[j].key.type == FD_QUIC_PKT_META_TYPE_STREAM_DATA ) {
        ulong stream_id = FD_QUIC_PKT_META_STREAM_ID( pkt_meta->var[j].key );
        fd_quic_tx_stream_treap_t * conn_streams = conn->tx_streams;
        fd_quic_tx_stream_pool_t *  tx_streams   = state->tx_streams;
        fd_quic_tx_stream_t *       tx_pool      = fd_quic_tx_stream_pool( tx_streams );
        fd_quic_tx_stream_t *       stream       = fd_quic_tx_stream_treap_ele_query( conn_streams, stream_id, tx_pool );
        if( FD_UNLIKELY( !stream ) ) {
          FD_LOG_WARNING(( "received ACK for unknown stream. This is a bug" ));
          continue;
        }
        fd_quic_tx_stream_free( tx_streams, stream );
      }
    }
  }
}

/* process lost packets
   These packets will be declared lost and relevant data potentially resent */
void
fd_quic_process_lost( fd_quic_conn_t * conn,
                      uint             enc_level,
                      ulong            cnt ) {
  /* start at oldest sent */
  fd_quic_pkt_meta_t *      pool = fd_quic_get_state( conn->quic )->pkt_meta_pool;
  fd_quic_pkt_meta_list_t * sent = &conn->sent_pkt_meta[enc_level];

  fd_quic_pkt_meta_list_iter_t iter = fd_quic_pkt_meta_list_iter_fwd_init( sent, pool );
  for( ulong j=0UL; j<cnt && !fd_quic_pkt_meta_list_iter_done( iter, sent, pool ); j++ ) {
    fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_list_iter_ele( iter, sent, pool );
    pkt_meta->expiry = 0; /* force expiry */
  }

  /* do the processing */
  fd_quic_pkt_meta_retry( conn->quic, conn, 0 /* don't force */, enc_level );
}

/* process ack range
   applies to pkt_number in [largest_ack - ack_range, largest_ack] */
void
fd_quic_process_ack_range( fd_quic_conn_t * conn,
                           uint             enc_level,
                           ulong            largest_ack,
                           ulong            ack_range ) {
  /* loop thru all packet metadata, and process individual metadata */

  /* inclusive range */
  ulong hi = largest_ack;
  ulong lo = largest_ack - ack_range;

  /* start at oldest sent */
  fd_quic_state_t *            state = fd_quic_get_state( conn->quic );
  fd_quic_pkt_meta_t *         pool  = state->pkt_meta_pool;
  fd_quic_pkt_meta_list_t *    sent  = &conn->sent_pkt_meta[enc_level];
  fd_quic_pkt_meta_list_iter_t iter  = fd_quic_pkt_meta_list_iter_fwd_init( sent, pool );
  fd_quic_pkt_meta_list_iter_t prior = UINT_MAX;

  /* seek to first packet in ACK range */
  while( !fd_quic_pkt_meta_list_iter_done( iter, sent, pool ) ) {
    if( fd_quic_pkt_meta_list_iter_ele( iter, sent, pool )->pkt_number >= lo ) break;
    prior = iter;
    iter  = fd_quic_pkt_meta_list_iter_fwd_next( iter, sent, pool );
  }

  /* reclaim all packets in range */
  ulong reclaim_cnt = 0UL;
  while( !fd_quic_pkt_meta_list_iter_done( iter, sent, pool ) ) {
    ulong pkt_meta_idx = fd_quic_pkt_meta_list_iter_idx( iter, sent, pool );
    if( pool[pkt_meta_idx].pkt_number > hi ) break;
    /* TODO bulk reclaim stream buffers */
    fd_quic_reclaim_pkt_meta( conn, pool+pkt_meta_idx, enc_level );
    fd_quic_pkt_meta_list_idx_remove( sent, pkt_meta_idx, prior, pool );
    fd_quic_pkt_meta_list_idx_push_head( state->pkt_meta_free, pkt_meta_idx, pool );
    iter = prior!=UINT_MAX ? fd_quic_pkt_meta_list_iter_fwd_next( prior, sent, pool )
                           : fd_quic_pkt_meta_list_iter_fwd_init( sent, pool );
    reclaim_cnt++;
  }

  (void)reclaim_cnt;
  FD_DEBUG( FD_LOG_DEBUG(( "conn=%p recv ACK for enc=%u range=[%lu,%lu) reclaim_cnt=%lu",
      (void *)conn, enc_level, lo, hi+1, reclaim_cnt )) );
}

static ulong
fd_quic_frame_handle_ack_frame(
    void * vp_context,
    fd_quic_ack_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)vp_context;
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  uint enc_level = context.pkt->enc_level;

  if( FD_UNLIKELY( data->first_ack_range > data->largest_ack ) ) {
    /* this is a protocol violation, so inform the peer */
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  /* track lowest packet ack'd */
  ulong low_ack_pkt_number = data->largest_ack - data->first_ack_range;

  /* ack packets are not ack-eliciting (they are acked with other things) */

  /* process ack range
     applies to pkt_number in [largest_ack - first_ack_range, largest_ack] */
  fd_quic_process_ack_range( context.conn, enc_level, data->largest_ack, data->first_ack_range );

  uchar const * p_str = p;
  uchar const * p_end = p + p_sz;

  ulong ack_range_count = data->ack_range_count;

  /* cur_pkt_number holds the packet number of the lowest processed
     and acknowledged packet
     This should always be a valid packet number >= 0 */
  ulong cur_pkt_number = data->largest_ack - data->first_ack_range;

  /* walk thru ack ranges */
  for( ulong j = 0UL; j < ack_range_count; ++j ) {
    if( FD_UNLIKELY(  p_end <= p ) ) return FD_QUIC_PARSE_FAIL;

    fd_quic_ack_range_frag_t ack_range[1];
    ulong rc = fd_quic_decode_ack_range_frag( ack_range, p, (ulong)( p_end - p ) );
    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;

    /* ensure we have ulong local vars, regardless of ack_range definition */
    ulong gap    = (ulong)ack_range->gap;
    ulong length = (ulong)ack_range->length;

    /* sanity check before unsigned arithmetic */
    if( FD_UNLIKELY( ( gap    > ( ~0x3UL ) ) |
                     ( length > ( ~0x3UL ) ) ) ) {
      /* This is an unreasonably large value, so fail with protocol violation
         It's also likely impossible due to the encoding method */
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
      return FD_QUIC_PARSE_FAIL;
    }

    /* The number of packet numbers to skip (they are not being acked) is
       ack_range->gap + 2
       This is +1 to get from the lowest acked packet to the highest unacked packet
       and +1 because the count of packets in the gap is (ack_range->gap+1) */
    ulong skip = gap + 2UL;

    /* verify the skip and length values are valid */
    if( FD_UNLIKELY( skip + length > cur_pkt_number ) ) {
      /* this is a protocol violation, so inform the peer */
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
      return FD_QUIC_PARSE_FAIL;
    }

    /* track lowest */
    ulong lo_pkt_number = cur_pkt_number - skip - length;
    low_ack_pkt_number = fd_ulong_min( low_ack_pkt_number, lo_pkt_number );

    /* process ack range */
    fd_quic_process_ack_range( context.conn, enc_level, cur_pkt_number - skip, length );

    /* Find the next lowest processed and acknowledged packet number
       This should get us to the next lowest processed and acknowledged packet
       number */
    cur_pkt_number -= skip + length;

    p += rc;
  }

  /* process lost packets */
  do {
    fd_quic_pkt_meta_t *      pool     = fd_quic_get_state( context.quic )->pkt_meta_pool;
    fd_quic_pkt_meta_list_t * sent     = &context.conn->sent_pkt_meta[enc_level];
    if( fd_quic_pkt_meta_list_is_empty( sent ) ) break;
    fd_quic_pkt_meta_t *      pkt_meta = fd_quic_pkt_meta_list_ele_peek_head( sent, pool );
    if( pkt_meta->pkt_number >= low_ack_pkt_number ) break;
    ulong skipped = 0UL;
    while( FD_LIKELY( pkt_meta && pkt_meta->pkt_number < low_ack_pkt_number  ) ) {
      skipped++;
      pkt_meta = pkt_meta->next==UINT_MAX ? NULL : pool + pkt_meta->next;
    }

    if( FD_UNLIKELY( skipped > 3 ) ) {
      fd_quic_process_lost( context.conn, enc_level, skipped - 3 );
    }
  } while(0);

  /* ECN counts
     we currently ignore them, but we must process them to get to the following bytes */
  if( data->type & 1U ) {
    if( FD_UNLIKELY(  p_end <= p ) ) return FD_QUIC_PARSE_FAIL;

    fd_quic_ecn_counts_frag_t ecn_counts[1];
    ulong rc = fd_quic_decode_ecn_counts_frag( ecn_counts, p, (ulong)( p_end - p ) );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    p += rc;
  }

  return (ulong)( p - p_str );
}

static ulong
fd_quic_frame_handle_reset_stream_frame(
    void * context,
    fd_quic_reset_stream_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  /* ack-eliciting */
  /* TODO implement */
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_stop_sending_frame(
    void *                         vp_context,
    fd_quic_stop_sending_frame_t * data,
    uchar const *                  p,
    ulong                          p_sz ) {
  (void)data; (void)p; (void)p_sz;
  fd_quic_frame_context_t * context = vp_context;
  context->pkt->ack_flag |= ACK_FLAG_RQD;  /* ack-eliciting */
  return 0UL;
}

static ulong
fd_quic_frame_handle_new_token_frame(
    void * context,
    fd_quic_new_token_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  /* ack-eliciting */
  return FD_QUIC_PARSE_FAIL;
}

static void
fd_quic_cb_stream_receive(
    fd_quic_frame_context_t const * ctx,
    ulong                           stream_id,
    uchar const *                   data,
    ulong                           data_sz,
    ulong                           offset,
    int                             fin
) {
  fd_quic_t *       quic = ctx->quic;
  fd_quic_conn_t *  conn = ctx->conn;

  if( FD_UNLIKELY( !quic->cb.stream_receive ) ) return;
  quic->cb.stream_receive( quic->cb.quic_ctx, conn, stream_id, data, data_sz, offset, fin );

  /* update metrics */
  quic->metrics.stream_rx_event_cnt++;
  quic->metrics.stream_rx_byte_cnt += data_sz;
  if( fin ) {
    fd_rollset_insert( &conn->fin_streams, stream_id>>2 );
  }
}

static ulong
fd_quic_frame_handle_stream_frame(
    void *                   vp_context,
    fd_quic_stream_frame_t * data,
    uchar const *            p,
    ulong                    p_sz ) {

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;
  fd_quic_state_t *       state   = fd_quic_get_state( context.quic );
  fd_quic_conn_t *        conn    = context.conn;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* offset field is optional, implied 0 */
  ulong offset      = fd_ulong_if( data->offset_opt, data->offset, 0UL );
  ulong stream_id   = data->stream_id;
  ulong stream_type = stream_id & 3UL;
  ulong data_sz     = fd_ulong_if( data->length_opt, data->length, p_sz );
  int   is_fin      = data->fin_opt;

  /* only handle unidirectional client-initiated data */
  if( FD_UNLIKELY( context.quic->config.role != FD_QUIC_ROLE_SERVER ||
                   stream_type != FD_QUIC_STREAM_TYPE_UNI_CLIENT ) ) {
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  /* bounds check data */
  if( FD_UNLIKELY( data_sz > p_sz ) ) {
    /* FIXME throw a conn error here? */
    FD_DEBUG( FD_LOG_DEBUG(( "Stream header claims %lu bytes but only %lu bytes found", data_sz, p_sz )); )
    return FD_QUIC_PARSE_FAIL;
  }

  /* stream_id outside allowed range - protocol error */
  if( FD_UNLIKELY( stream_id >= context.conn->rx_sup_stream_id ) ) {
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  /* data outside of allowed range - protocol error */
  if( FD_UNLIKELY(
      offset         >= FD_TXN_MTU ||
      data_sz        >  FD_TXN_MTU ||
      offset+data_sz >  FD_TXN_MTU
  ) ) {
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  conn->ack_gen->pending_bytes += data_sz;

  /* already completed this frame ID */
  if( fd_rollset_query( &conn->fin_streams, stream_id>>2 ) ) {
    /* FIXME metrics here */
    /* FIXME detect excessive retransmits */
    return data_sz;
  }

  /* fast path: stream data is not fragmented */
  if( offset==0 && is_fin ) {
    fd_quic_cb_stream_receive(
        &context,
        stream_id,
        p, p_sz,
        0, /* offset */
        1  /* fin */
    );
    return p_sz;
  }

  /* slow path: stream data is fragmented (at least one more frame in
     addition to this one required to recover all stream data) ... */
  ulong defrag_stream_id = state->defrag_stream_id;
  if( defrag_stream_id != stream_id ) {

    if( offset==0UL ) {
      /* Cancel current defrag and start new */
      defrag_stream_id = stream_id;
      /* FIXME STOP_SENDING for current stream */
      /* FIXME metrics */
    } else {
      /* Out-of-order stream fragment, can't defragment.  ACK regardless
         to avoid retransmission loops */
      /* FIXME metrics */
    }

  } else {

    ulong defrag_offset = state->defrag_offset;
    if( offset > defrag_offset ) {
      /* Out-of-order stream fragment.
         Inhibit ACK to elicit retransmission */
      /* FIXME metrics */
      context.pkt->ack_flag |= ACK_FLAG_CANCEL;
    } else {
      /* Continue defrag */
      ulong skip   = defrag_offset - offset;
      ulong new_sz = (ulong)fd_long_max( (long)data_sz - (long)skip, 0L );
      fd_quic_cb_stream_receive(
          &context,
          stream_id,
          p+skip, new_sz,
          defrag_stream_id,
          is_fin
      );
    }

  }

  /* packet bytes consumed */
  return data_sz;
}

static ulong
fd_quic_frame_handle_max_data_frame(
    void *                     vp_context,
    fd_quic_max_data_frame_t * data,
    uchar const *              p,
    ulong                     p_sz ) {
  /* unused */
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  ulong tx_max_data  = context.conn->tx_max_data;
  ulong new_max_data = data->max_data;

  /* max data is only allowed to increase the limit. Transgressing frames
     are silently ignored */
  context.conn->tx_max_data = new_max_data > tx_max_data ? new_max_data : tx_max_data;

  fd_quic_reschedule_conn( context.conn, 0 );

  return 0; /* no additional bytes consumed from buffer */
}

static ulong
fd_quic_frame_handle_max_stream_data(
    void *                      vp_context,
    fd_quic_max_stream_data_t * data FD_FN_UNUSED,
    uchar const *               p    FD_FN_UNUSED,
    ulong                       p_sz FD_FN_UNUSED ) {
  /* ack-eliciting */
  fd_quic_frame_context_t * context = vp_context;
  context->pkt->ack_flag |= ACK_FLAG_RQD;
  return 0;
}

static ulong
fd_quic_frame_handle_max_streams_frame(
    void *                        vp_context,
    fd_quic_max_streams_frame_t * data,
    uchar const *                 p,
    ulong                         p_sz) {
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* stream type */
  ulong type = (ulong)context.conn->server | (ulong)( data->stream_type << 1u );

  /* max streams is only allowed to increase the limit. Transgressing frames
     are silently ignored */
  ulong tx_sup_stream_id = data->max_streams * 4UL + type;
  context.conn->tx_sup_stream_id = fd_ulong_max( data->max_streams, tx_sup_stream_id );

  fd_quic_reschedule_conn( context.conn, 0 );

  return 0;
}

static ulong
fd_quic_frame_handle_data_blocked_frame(
      void *                         vp_context,
      fd_quic_data_blocked_frame_t * data,
      uchar const *                  p,
      ulong                          p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* Since we do not do runtime allocations, we will not attempt
     to find more memory in the case of DATA_BLOCKED
     We return 0 (bytes consumed), since this frame does not
     require any additional bytes from the packet */
  return 0;
}

static ulong
fd_quic_frame_handle_stream_data_blocked_frame(
      void *                                vp_context,
      fd_quic_stream_data_blocked_frame_t * data,
      uchar const *                         p,
      ulong                                 p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* Since we do not do runtime allocations, we will not attempt
     to find more memory in the case of STREAM_DATA_BLOCKED
     We return 0 (bytes consumed), since this frame does not
     require any additional bytes from the packet */
  return 0;
}

static ulong
fd_quic_frame_handle_streams_blocked_frame(
    void *                            vp_context,
    fd_quic_streams_blocked_frame_t * data,
    uchar const *                     p,
    ulong                             p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* STREAMS_BLOCKED should be sent by client when it wants
     to use a new stream, but is unable to due to the max_streams
     value
     We can support this in the future, but the solana-tpu client
     does not currently use it
     We could make a callback to allow the tile to choose whether
     to force close a connection to free up streams */

  return 0;
}

static ulong
fd_quic_frame_handle_new_conn_id_frame(
    void *                        vp_context,
    fd_quic_new_conn_id_frame_t * data,
    uchar const *                 p,
    ulong                         p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  fd_quic_conn_id_t peer_conn_id = {0};
  fd_memcpy( peer_conn_id.conn_id, data->conn_id, data->conn_id_len );
  peer_conn_id.sz = data->conn_id_len;

  fd_quic_conn_t * conn = context.conn;

  ulong peer_cnt = conn->peer_cnt;

  ulong max_peer_cnt = FD_QUIC_MAX_CONN_ID_PER_CONN;
  if( peer_cnt >= max_peer_cnt ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  fd_quic_endpoint_t * peer = &conn->peer[peer_cnt];

  /* copy current endpoint net values */
  /* TODO get from current packet? */
  *peer = conn->peer[conn->cur_peer_idx];

  /* replace connection id */
  peer->conn_id = peer_conn_id;

  /* insert into map */

  /* TODO implied retire to be implemented */
  FD_DEBUG( FD_LOG_WARNING(( "NEW_CONNECTION_ID  conn_idx: %u   retire_prior_to %lu", conn->conn_idx, data->retire_prior_to )); )

  /* update conn */
  //conn->cur_peer_idx = (ushort)peer_cnt;
  conn->peer_cnt     = (ushort)( peer_cnt+1 );

  return 0;
}

static ulong
fd_quic_frame_handle_retire_conn_id_frame(
      void *                           vp_context,
      fd_quic_retire_conn_id_frame_t * data,
      uchar const *                    p,
      ulong                            p_sz ) {
  (void)vp_context;
  (void)data;
  (void)p;
  (void)p_sz;
  FD_DEBUG( FD_LOG_DEBUG(( "retire_conn_id requested" )); )

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* TODO add support */

  return 0;
}

static ulong
fd_quic_frame_handle_path_challenge_frame(
    void * context,
    fd_quic_path_challenge_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_path_response_frame(
    void * context,
    fd_quic_path_response_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static void
fd_quic_frame_handle_conn_close_frame(
    void *                       vp_context ) {
  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* frame type 0x1c means no error, or only error at quic level
     frame type 0x1d means error at application layer
     TODO provide APP with this info */
  (void)context;
  FD_DEBUG( FD_LOG_DEBUG(( "peer requested close" )) );

  switch( context.conn->state ) {
    case FD_QUIC_CONN_STATE_PEER_CLOSE:
    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
      return;

    default:
      context.conn->state = FD_QUIC_CONN_STATE_PEER_CLOSE;
  }

  context.conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
  fd_quic_reschedule_conn( context.conn, 0 );
}

static ulong
fd_quic_frame_handle_conn_close_0_frame(
    void *                         vp_context,
    fd_quic_conn_close_0_frame_t * data,
    uchar const *                  p,
    ulong                          p_sz ) {
  (void)p;

  ulong reason_phrase_length = data->reason_phrase_length;
  if( FD_UNLIKELY( reason_phrase_length > p_sz ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* the information here can be invaluble for debugging */
  FD_DEBUG(
    char reason_buf[256] = {0};
    ulong reason_len = fd_ulong_min( sizeof(reason_buf)-1, reason_phrase_length );
    memcpy( reason_buf, p, reason_len );

    FD_LOG_WARNING(( "fd_quic_frame_handle_conn_close_frame - "
        "error_code: %lu  "
        "frame_type: %lx  "
        "reason: %s",
        data->error_code,
        data->frame_type,
        reason_buf ));
  );

  fd_quic_frame_handle_conn_close_frame( vp_context );

  return reason_phrase_length;
}

static ulong
fd_quic_frame_handle_conn_close_1_frame(
    void *                         vp_context,
    fd_quic_conn_close_1_frame_t * data,
    uchar const *                  p,
    ulong                          p_sz ) {
  (void)p;

  ulong reason_phrase_length = data->reason_phrase_length;
  if( FD_UNLIKELY( reason_phrase_length > p_sz ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* the information here can be invaluble for debugging */
  FD_DEBUG(
    char reason_buf[256] = {0};
    ulong reason_len = fd_ulong_min( sizeof(reason_buf)-1, reason_phrase_length );
    memcpy( reason_buf, p, reason_len );

    FD_LOG_WARNING(( "fd_quic_frame_handle_conn_close_frame - "
        "error_code: %lu  "
        "reason: %s",
        data->error_code,
        reason_buf ));
  );

  fd_quic_frame_handle_conn_close_frame( vp_context );

  return reason_phrase_length;
}

static ulong
fd_quic_frame_handle_handshake_done_frame(
    void *                           vp_context,
    fd_quic_handshake_done_frame_t * data,
    uchar const *                    p,
    ulong                            p_sz) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;
  fd_quic_conn_t *        conn    = context.conn;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* servers must treat receipt of HANDSHAKE_DONE as a protocol violation */
  if( FD_UNLIKELY( conn->server ) ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) ) {
    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_PEER_CLOSE:
      case FD_QUIC_CONN_STATE_ABORT:
      case FD_QUIC_CONN_STATE_CLOSE_PENDING:
        /* connection closing... nothing to do */
        return 0;

      case FD_QUIC_CONN_STATE_HANDSHAKE:
        /* still handshaking... assume packet was reordered */
        return FD_QUIC_PARSE_FAIL;

      case FD_QUIC_CONN_STATE_ACTIVE:
        /* duplicate frame? */
        return 0;
    }

    return FD_QUIC_PARSE_FAIL;
  }

  /* RFC 9001 4.9.2. Discarding Handshake Keys
     > An endpoint MUST discard its Handshake keys when the
     > TLS handshake is confirmed
     RFC 9001 4.1.2. Handshake Confirmed
     > At the client, the handshake is considered confirmed when a
     > HANDSHAKE_DONE frame is received. */
  fd_quic_abandon_enc_level( conn, fd_quic_enc_level_handshake_id );

  if( FD_UNLIKELY( !conn->tls_hs ) ) {
    /* sanity check */
    return 0;
  }

  /* we shouldn't be receiving this unless handshake is complete */
  conn->state = FD_QUIC_CONN_STATE_ACTIVE;

  /* user callback */
  fd_quic_cb_conn_hs_complete( conn->quic, conn );

  if( conn->tls_hs ) {
    /* eliminate any remaining hs_data at application level */
    fd_quic_tls_hs_data_t * hs_data = NULL;

    uint hs_enc_level = fd_quic_enc_level_appdata_id;
    hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, hs_enc_level );
    /* skip packets we've sent */
    while( hs_data ) {
      fd_quic_tls_pop_hs_data( conn->tls_hs, hs_enc_level );

      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, hs_enc_level );
    }

    /* Deallocate tls_hs once completed */
    fd_quic_tls_hs_delete( conn->tls_hs );
    conn->tls_hs = NULL;
  }


  return 0;
}

/* initiate the shutdown of a connection
   may select a reason code */
void
fd_quic_conn_close( fd_quic_conn_t * conn,
                    uint             app_reason ) {
  if( FD_UNLIKELY( !conn ) ) return;

  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_DEAD:
    case FD_QUIC_CONN_STATE_ABORT:
      return; /* close has no effect in these states */

    default:
      {
        conn->state      = FD_QUIC_CONN_STATE_CLOSE_PENDING;
        conn->app_reason = app_reason;
      }
  }

  /* set connection to be serviced ASAP */
  fd_quic_reschedule_conn( conn, 0 );
}
