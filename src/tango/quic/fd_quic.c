#include "fd_quic.h"
#include "fd_quic_common.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_proto.h"

#include "crypto/fd_quic_crypto_suites.h"
#include "templ/fd_quic_transport_params.h"
#include "templ/fd_quic_parse_util.h"
#include "tls/fd_quic_tls.h"
#include "../ip/fd_ip.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>   /* for keylog open(2)  */
#include <unistd.h>  /* for keylog close(2) */

// TODO ugly -- remove TLS dependency here
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../ballet/x509/fd_x509_openssl.h"
#include <openssl/rand.h>

#define CONN_FMT "%02x%02x%02x%02x%02x%02x%02x%02x"
#define CONN_ID(CONN_ID) (CONN_ID)->conn_id[0], (CONN_ID)->conn_id[1], (CONN_ID)->conn_id[2], (CONN_ID)->conn_id[3],  \
                         (CONN_ID)->conn_id[4], (CONN_ID)->conn_id[5], (CONN_ID)->conn_id[6], (CONN_ID)->conn_id[7]

/* Declare priority queue for time based processing */
#define PRQ_NAME      service_queue
#define PRQ_T         fd_quic_event_t
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"

/* Declare map type for stream_id -> stream* */
#define MAP_NAME              fd_quic_stream_map
#define MAP_KEY               stream_id
#define MAP_T                 fd_quic_stream_map_t
#define MAP_KEY_NULL          FD_QUIC_STREAM_ID_UNUSED
#define MAP_KEY_INVAL(key)    ((key)==MAP_KEY_NULL)
#define MAP_QUERY_OPT         1
#include "../../util/tmpl/fd_map_dynamic.c"

/* Construction API ***************************************************/

FD_QUIC_API FD_FN_CONST ulong
fd_quic_align( void ) {
  return FD_QUIC_ALIGN;
}

/* fd_quic_layout_t describes the memory layout of an fd_quic_t */
struct fd_quic_layout {
  ulong conns_off;       /* offset of connection mem region  */
  ulong conn_footprint;  /* sizeof a conn                    */
  ulong conn_map_off;    /* offset of conn map mem region    */
  ulong event_queue_off; /* offset of event queue mem region */
  int   lg_slot_cnt;     /* see conn_map_new                 */
  ulong tls_off;         /* offset of fd_quic_tls_t          */
  ulong ip_off;          /* offset of fd_ip_t                */
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
  double conn_id_sparsity = limits->conn_id_sparsity;
  ulong  handshake_cnt    = limits->handshake_cnt;
  ulong  inflight_pkt_cnt = limits->inflight_pkt_cnt;
  ulong  tx_buf_sz        = limits->tx_buf_sz;

  if( FD_UNLIKELY( conn_cnt        ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( handshake_cnt   ==0UL ) ) return 0UL;
  if( FD_UNLIKELY( inflight_pkt_cnt==0UL ) ) return 0UL;
  if( FD_UNLIKELY( tx_buf_sz       ==0UL ) ) return 0UL;

  if( FD_UNLIKELY( conn_id_sparsity==0.0 ) )
    conn_id_sparsity = FD_QUIC_DEFAULT_SPARSITY;
  if( FD_UNLIKELY( conn_id_cnt < FD_QUIC_MIN_CONN_ID_CNT ))
    return 0UL;

  ulong offs  = 0;

  /* allocate space for fd_quic_t */
  offs += sizeof(fd_quic_t);

  /* allocate space for state */
  offs  = fd_ulong_align_up( offs, alignof(fd_quic_state_t) );
  offs += sizeof(fd_quic_state_t);

  /* allocate space for connections */
  offs                    = fd_ulong_align_up( offs, fd_quic_conn_align() );
  layout->conns_off       = offs;
  ulong conn_footprint    = fd_quic_conn_footprint( limits );
  if( FD_UNLIKELY( !conn_footprint ) ) { FD_LOG_WARNING(( "invalid fd_quic_conn_footprint" )); return 0UL; }
  layout->conn_footprint  = conn_footprint;
  ulong conn_foot_tot     = conn_cnt * conn_footprint;
  offs                   += conn_foot_tot;

  /* allocate space for conn IDs */
  offs                     = fd_ulong_align_up( offs, fd_quic_conn_map_align() );
  layout->conn_map_off     = offs;
  ulong slot_cnt_bound     = (ulong)( conn_id_sparsity * (double)conn_cnt * (double)conn_id_cnt );
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
  ulong tls_footprint  = fd_quic_tls_footprint( limits->handshake_cnt );
  if( FD_UNLIKELY( !tls_footprint ) ) { FD_LOG_WARNING(( "invalid fd_quic_tls_footprint" )); return 0UL; }
  offs                += tls_footprint;

  return offs;
}

FD_QUIC_API FD_FN_PURE ulong
fd_quic_footprint( fd_quic_limits_t const * limits ) {
  fd_quic_layout_t layout;
  return fd_quic_footprint_ext( limits, &layout );
}

FD_QUIC_API void *
fd_quic_new( void * mem,
             fd_quic_limits_t const * limits,
             fd_ip_t * ip ) {

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
                 | ( limits->inflight_pkt_cnt==0UL )
                 | ( limits->tx_buf_sz       ==0UL ) ) ) {
    return 0UL;
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

  if( !ip ) {
    FD_LOG_WARNING(( "NULL fd_ip" ));
    return NULL;
  }
  quic->ip = ip;

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

  limits->conn_cnt         = fd_env_strip_cmdline_ulong( pargc, pargv, "--quic-conns",         "QUIC_CONN_CNT",        1024UL );
  limits->conn_id_cnt      = fd_env_strip_cmdline_ulong( pargc, pargv, "--quic-conn-ids",      "QUIC_CONN_ID_CNT",       16UL );
  ulong stream_cnt         = fd_env_strip_cmdline_uint ( pargc, pargv, "--quic-streams",       "QUIC_STREAM_CNT",         2UL );
  limits->handshake_cnt    = fd_env_strip_cmdline_uint ( pargc, pargv, "--quic-handshakes",    "QUIC_HANDSHAKE_CNT",    256UL );
  limits->inflight_pkt_cnt = fd_env_strip_cmdline_ulong( pargc, pargv, "--quic-inflight-pkts", "QUIC_MAX_INFLIGHT_PKTS", 64UL );
  limits->tx_buf_sz        = fd_env_strip_cmdline_ulong( pargc, pargv, "--quic-tx-buf-sz",     "QUIC_TX_BUF_SZ",    1UL<<15UL );

  limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ] = 0UL;
  limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ] = 0UL;
  limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT  ] = stream_cnt;
  limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER  ] = 0UL;

  return limits;
}

FD_QUIC_API fd_quic_config_t *
fd_quic_config_from_env( int  *             pargc,
                         char ***           pargv,
                         fd_quic_config_t * cfg ) {

  if( FD_UNLIKELY( !cfg ) ) return NULL;

  char const * keylog_file     = fd_env_strip_cmdline_cstr ( pargc, pargv, NULL,             "SSLKEYLOGFILE", NULL  );
  ulong        idle_timeout_ms = fd_env_strip_cmdline_ulong( pargc, pargv, "--idle-timeout", NULL,            100UL );
  ulong        initial_rx_max_stream_data = fd_env_strip_cmdline_ulong(
      pargc,
      pargv,
      "--quic-initial-rx-max-stream-data",
      "QUIC_INITIAL_RX_MAX_STREAM_DATA",
      FD_QUIC_DEFAULT_INITIAL_RX_MAX_STREAM_DATA
  );

  if( keylog_file ) {
    strncpy( cfg->keylog_file, keylog_file, FD_QUIC_CERT_PATH_LEN );
  } else {
    cfg->keylog_file[0]='\0';
  }

  cfg->idle_timeout = idle_timeout_ms * (ulong)1e6;
  cfg->initial_rx_max_stream_data = initial_rx_max_stream_data;

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

/* initialize everything that mutates during runtime */
static void
fd_quic_stream_init( fd_quic_stream_t * stream ) {
  stream->context            = NULL;

  stream->tx_buf.head        = 0;
  stream->tx_buf.tail        = 0;
  stream->tx_sent            = 0;
  memset( stream->tx_ack, 0, stream->tx_buf.cap >> 3ul );

  stream->stream_flags       = 0;
  /* don't update next here, since it's still in use */

  stream->state              = 0;

  stream->tx_max_stream_data = 0;
  stream->tx_tot_data        = 0;
  stream->tx_last_byte       = 0;

  stream->rx_max_stream_data = 0;
  stream->rx_tot_data        = 0;

  stream->upd_pkt_number     = 0;
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

  if( FD_UNLIKELY( !config->role          ) ) { FD_LOG_WARNING(( "cfg.role not set"      )); return NULL; }
  if( FD_UNLIKELY( !config->idle_timeout  ) ) { FD_LOG_WARNING(( "zero cfg.idle_timeout" )); return NULL; }

  if( FD_UNLIKELY( (!quic->cert_object) | (!quic->cert_key_object) ) ) {
    /* FIXME remove this hack by separating TLS and QUIC management.
             User should provide pre-initialized SSL_CTX with cert
             installed.  fd_quic should not touch any certificate
             handling. */
    FD_LOG_WARNING(( "Warning: Certificate or key not set. Generating random." ));
    if( FD_UNLIKELY( quic->cert_object     ) ) X509_free    ( (X509 *)quic->cert_object         );
    if( FD_UNLIKELY( quic->cert_key_object ) ) EVP_PKEY_free( (EVP_PKEY *)quic->cert_key_object );

    /* Generate certificate key */
    uchar cert_private_key[ 32 ];
    FD_TEST( 1==RAND_bytes( cert_private_key, 32 ) );
    EVP_PKEY * cert_pkey = fd_ed25519_pkey_from_private( cert_private_key );
    FD_TEST( cert_pkey );

    /* Generate X509 certificate */
    X509 * cert = fd_x509_gen_solana_cert( cert_pkey );
    FD_TEST( cert );

    quic->cert_key_object = cert_pkey;
    quic->cert_object     = cert;
  }

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
  fd_quic_conn_t * last = NULL;
  for( ulong j = 0; j < limits->conn_cnt; ++j ) {
    void * conn_mem  = (void *)( conn_laddr );
    conn_laddr      += layout.conn_footprint;

    fd_quic_conn_t * conn = fd_quic_conn_new( conn_mem, quic, limits );
    if( FD_UNLIKELY( !conn ) ) {
      FD_LOG_WARNING(( "NULL conn" ));
      return NULL;
    }

    conn->next = 0L;
    /* start with minimum supported max datagram */
    /* peers may allow more */
    conn->tx_max_datagram_sz = FD_QUIC_INITIAL_PAYLOAD_SZ_MAX;

    if( !last ) state->conns = conn;
    else        last ->next  = conn;

    last = conn;
  }

  /* State: Initialize conn ID map */

  ulong  conn_map_laddr = (ulong)quic + layout.conn_map_off;
  state->conn_map = fd_quic_conn_map_new( (void *)conn_map_laddr, layout.lg_slot_cnt );
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

  /* Prepare keylog file */

  char const * keylog_file = config->keylog_file;
  int keylog_fd = -1;
  if( FD_UNLIKELY( keylog_file[0] ) ) {
    keylog_fd = open( keylog_file, O_WRONLY|O_CREAT|O_APPEND, 0660 );
    if( FD_UNLIKELY( keylog_fd<0 ) )
      FD_LOG_WARNING(( "Cannot create keylog file at %s (%i-%s)", keylog_file, errno, fd_io_strerror( errno ) ));
    else
      FD_LOG_INFO(( "Logging TLS key material to %s", keylog_file ));
  }
  state->keylog_fd = keylog_fd;

  /* Check TX AIO */

  if( FD_UNLIKELY( !quic->aio_tx.send_func ) ) {
    FD_LOG_WARNING(( "NULL aio_tx" ));
    return NULL;
  }

  /* State: Initialize TLS */

  fd_quic_tls_cfg_t tls_cfg = {
    .max_concur_handshakes = limits->handshake_cnt,

    /* set up callbacks */
    .client_hello_cb       = fd_quic_tls_cb_client_hello,
    .alert_cb              = fd_quic_tls_cb_alert,
    .secret_cb             = fd_quic_tls_cb_secret,
    .handshake_complete_cb = fd_quic_tls_cb_handshake_complete,
    .keylog_cb             = fd_quic_tls_cb_keylog,

    /* set up alpn */
    .alpns                 = (uchar const *)config->alpns,
    .alpns_sz              = config->alpns_sz,

    .keylog_fd             = keylog_fd
  };
  tls_cfg.cert     = (X509 *)    quic->cert_object;     quic->cert_object     = NULL;
  tls_cfg.cert_key = (EVP_PKEY *)quic->cert_key_object; quic->cert_key_object = NULL;

  ulong tls_laddr = (ulong)quic + layout.tls_off;
  state->tls = fd_quic_tls_new( (void *)tls_laddr, &tls_cfg );
  if( FD_UNLIKELY( !state->tls ) ) {
    quic->metrics.hs_err_alloc_fail_cnt++;
    FD_DEBUG( FD_LOG_WARNING( ( "fd_quic_tls_new failed" ) ) );
    return NULL;
  }
  quic->metrics.hs_created_cnt++;

  /* Initialize crypto */

  fd_quic_crypto_ctx_init( state->crypto_ctx );

  /* Initialize transport params */

  /* total data that may be sent on the connection is rx_buf_sz per stream,
     four types of stream */
  ulong tot_initial_max_data = config->initial_rx_max_stream_data * (
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT  ] +
    limits->stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER  ] );

  fd_quic_transport_params_t * tp = &state->transport_params;

  ulong initial_max_streams_bidi = limits->stream_cnt[ config->role==FD_QUIC_ROLE_SERVER ? FD_QUIC_STREAM_TYPE_BIDI_CLIENT : FD_QUIC_STREAM_TYPE_BIDI_SERVER ];
  ulong initial_max_streams_uni  = limits->stream_cnt[ config->role==FD_QUIC_ROLE_SERVER ? FD_QUIC_STREAM_TYPE_UNI_CLIENT  : FD_QUIC_STREAM_TYPE_UNI_SERVER  ];
  ulong initial_max_stream_data  = config->initial_rx_max_stream_data;

  memset( tp, 0, sizeof(fd_quic_transport_params_t) );
  ulong idle_timeout_ms = (config->idle_timeout + 1000000UL - 1UL) / 1000000UL;
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_idle_timeout,                    idle_timeout_ms          );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_udp_payload_size,                FD_QUIC_MAX_PAYLOAD_SZ   ); /* TODO */
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_data,                    tot_initial_max_data     );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_stream_data_bidi_local,  initial_max_stream_data  );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_stream_data_bidi_remote, initial_max_stream_data  );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_stream_data_uni,         initial_max_stream_data  );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_streams_bidi,            initial_max_streams_bidi );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, initial_max_streams_uni,             initial_max_streams_uni  );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, ack_delay_exponent,                  0                        ); /* TODO */
  FD_QUIC_TRANSPORT_PARAM_SET( tp, max_ack_delay,                       10                       ); /* TODO */
  FD_QUIC_TRANSPORT_PARAM_SET( tp, disable_active_migration,            1                        );
  FD_QUIC_TRANSPORT_PARAM_SET( tp, active_connection_id_limit,          limits->conn_id_cnt      ); /* TODO */


  /* Initialize next ephemeral udp port */
  state->next_ephem_udp_port = config->net.ephem_udp_port.lo;

  return quic;
}

/* get pointer to fd_ip_t */
fd_ip_t *
fd_quic_get_ip( fd_quic_t * quic ) {
  return quic->ip;
}

/* fd_quic_enc_level_to_pn_space maps of encryption level in [0,4) to
   packet number space. */
static uint
fd_quic_enc_level_to_pn_space( uint enc_level ) {
  /* TODO improve this map */
  static uchar el2pn_map[] = { 0, 2, 1, 2 };

  if( FD_UNLIKELY( enc_level >= 4 ) )
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
                    uint             reason ) {
  if( FD_UNLIKELY( conn->state == FD_QUIC_CONN_STATE_DEAD ) ) return;

  FD_LOG_WARNING(( "Connection terminating with reason code %u", reason ));
  conn->state  = FD_QUIC_CONN_STATE_ABORT;
  conn->reason = reason;

  /* set connection to be serviced ASAP */
  fd_quic_reschedule_conn( conn, 0 );
}

/* returns the encoding level we should use for the next tx quic packet
   or all 1's if nothing to tx */
uint
fd_quic_tx_enc_level( fd_quic_conn_t * conn ) {
  uint enc_level = ~0u;

  uint  app_pn_space   = fd_quic_enc_level_to_pn_space( fd_quic_enc_level_appdata_id );
  ulong app_pkt_number = conn->pkt_number[app_pn_space];

  /* fd_quic_tx_enc_level( ... )
       check status - if closing, set based on handshake complete
       check for acks
         find lowest enc level
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
        } else if( conn->suites[ fd_quic_enc_level_handshake_id ] ) {
          return fd_quic_enc_level_handshake_id;
        } else {
          return fd_quic_enc_level_initial_id;
        }
      }
      return ~0u;

      /* TODO consider this optimization... but we want to ack all handshakes, even if there is stream_data */
    case FD_QUIC_CONN_STATE_ACTIVE:
      {
        /* optimization for case where we have stream data to send */

        /* find stream data to send */
        fd_quic_stream_t * sentinel = conn->send_streams;
        fd_quic_stream_t * stream   = sentinel->next;
        if( !stream->sentinel && stream->upd_pkt_number >= app_pkt_number ) {
          return fd_quic_enc_level_appdata_id;
        }
      }
  }

  /* get peer_enc_level */
  uint peer_enc_level = conn->peer_enc_level;

  /* Check for acks to send */

  /* TODO replace enc_level with pn_space for ack index
     not necessary until 0-rtt is supported */
  /* use "pending" aand "sent" lists for acks to speed up this check */
  for( uint k = peer_enc_level; k < 4; ++k ) {
    fd_quic_ack_t * cur_ack_head = conn->acks_tx[k];
    /* skip sent */
    while( cur_ack_head && cur_ack_head->flags & FD_QUIC_ACK_FLAGS_SENT ) {
      cur_ack_head = cur_ack_head->next;
    }
    /* do we have any in the chain that are mandatory? */
    if( cur_ack_head                                      &&
        !( cur_ack_head->flags & FD_QUIC_ACK_FLAGS_SENT ) &&
        cur_ack_head->flags & FD_QUIC_ACK_FLAGS_MANDATORY ) {
      return k;
    }
  }

  /* Check for handshake data to send */
  fd_quic_tls_hs_data_t * hs_data   = NULL;

  for( uint i = peer_enc_level; i < 4 && i < enc_level; ++i ) {
    if( enc_level == ~0u || enc_level == i ) {
      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, (int)i );
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

  /* if we have acks to send or handshake data, then use that enc_level */
  if( enc_level != ~0u ) return enc_level;

  /* handshake done? */
  if( FD_UNLIKELY( conn->handshake_done_send ) ) return fd_quic_enc_level_appdata_id;

  /* find stream data to send */
  fd_quic_stream_t * sentinel = conn->send_streams;
  fd_quic_stream_t * stream   = sentinel->next;
  if( !stream->sentinel && stream->upd_pkt_number >= app_pkt_number ) {
    return fd_quic_enc_level_appdata_id;
  }

  if( conn->flags && conn->upd_pkt_number >= app_pkt_number ) {
    enc_level = fd_quic_enc_level_appdata_id;
  }

  /* nothing to send */
  return ~0u;
}

void
fd_quic_conn_tx( fd_quic_t * quic, fd_quic_conn_t * conn );

typedef struct fd_quic_pkt fd_quic_pkt_t;
typedef struct fd_quic_frame_context fd_quic_frame_context_t;

struct fd_quic_frame_context {
  fd_quic_t *      quic;
  fd_quic_conn_t * conn;
  fd_quic_pkt_t *  pkt;
};

/* handle single v1 frames */
/* returns bytes consumed */
ulong
fd_quic_handle_v1_frame( fd_quic_t *       quic,
                         fd_quic_conn_t *  conn,
                         fd_quic_pkt_t *   pkt,
                         uchar const *     buf,
                         ulong             buf_sz,
                         fd_quic_frame_u * frame_union ) {
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

#include "templ/fd_quic_parse_frame.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

  FD_LOG_DEBUG(( "unexpected frame type: %d  at offset: %ld", (int)*p, (long)( p - buf ) ));

  // if we get here we didn't understand "frame type"
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

  /* Free conns */

  ulong conn_laddr = (ulong)quic + layout.conns_off;
  for( ulong i=0; i < quic->limits.conn_cnt; i++ ) {
    fd_quic_conn_t * conn  = (fd_quic_conn_t *)( conn_laddr );
    conn_laddr            += layout.conn_footprint;

    if( conn->state ) fd_quic_conn_free( quic, conn );
  }

  /* Deinit crypto */

  fd_quic_crypto_ctx_fini( state->crypto_ctx );

  /* Deinit TLS */

  fd_quic_tls_delete( state->tls ); state->tls = NULL;

  /* Close keylog file */

  if( state->keylog_fd >= 0 ) {
    close( state->keylog_fd );
    state->keylog_fd = -1;
  }

  /* Delete service queue */

  service_queue_delete( service_queue_leave( state->service_queue ) );
  state->service_queue = NULL;

  /* Delete conn ID map */

  fd_quic_conn_map_delete( state->conn_map );
  state->conn_map = NULL;

  /* Reset conn free list */

  state->conns    = NULL;

  /* Clear join-lifetime memory regions */

  quic->cert_object     = NULL;
  quic->cert_key_object = NULL;

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

fd_quic_stream_t *
fd_quic_conn_new_stream( fd_quic_conn_t * conn,
                         int              dirtype ) {
  dirtype &= 1;

  fd_quic_t * quic = conn->quic;

  uint server = (uint)conn->server;
  uint type   = server + ( (uint)dirtype << 1u );

  ulong next_stream_id  = conn->next_stream_id[type];
  uint  stream_cnt      = (uint)conn->quic->limits.stream_cnt[type];
  uint  cur_num_streams = (uint)conn->num_streams[type];

  /* have we maxed out our max stream id?? */
  ulong max_stream_id = ( conn->max_streams[type] << 2u ) + type;
  if( FD_UNLIKELY( ( next_stream_id  >  max_stream_id ) |
                   ( conn->state     != FD_QUIC_CONN_STATE_ACTIVE ) |
                   ( cur_num_streams >= stream_cnt ) ) ) {
    /* this is a normal condition which occurs whenever we run up to
       the peer advertised limit and represents one form of flow control */
    return NULL;
  }

  /* find unused stream */
  fd_quic_stream_t * stream = conn->unused_streams->next;

  /* should not occur
     implies logic error */
  if( FD_UNLIKELY( stream == conn->unused_streams ) ) {
    FD_LOG_WARNING(( "max_concur_streams not reached, yet no free streams found" ));
    fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );

    return NULL;
  }

  /* remove from unused list */
  FD_QUIC_STREAM_LIST_REMOVE( stream );

  fd_quic_stream_init( stream );

  /* 0x00 Client-Initiated, Bidirectional
     0x01 Server-Initiated, Bidirectional
     0x02 Client-Initiated, Unidirectional
     0x03 Server-Initiated, Unidirectional */

  /* generate a new stream id */
  conn->next_stream_id[type] = next_stream_id + 4;

  /* track current number of streams */
  conn->num_streams[type]++;

  /* stream tx_buf already set */
  stream->conn      = conn;
  stream->stream_id = next_stream_id;
  stream->context   = NULL;

  /* set the max stream data to the appropriate initial value */
  stream->tx_max_stream_data = ( dirtype == FD_QUIC_TYPE_BIDIR )
                                   ? conn->tx_initial_max_stream_data_bidi_local
                                   : conn->tx_initial_max_stream_data_uni;

  /* probably we should add rx_buf */
  stream->rx_max_stream_data = ( dirtype == FD_QUIC_TYPE_BIDIR )
                                   ? conn->rx_initial_max_stream_data_bidi_local
                                   : 0ul;

  /* set state depending on stream type */
  stream->state = 0u;
  if( dirtype != FD_QUIC_TYPE_BIDIR ) {
    stream->state |= FD_QUIC_STREAM_STATE_RX_FIN;
  }

  stream->stream_flags = 0u;

  /* add to map of stream ids */
  fd_quic_stream_map_t * entry = fd_quic_stream_map_insert( conn->stream_map, next_stream_id );
  if( FD_UNLIKELY( !entry ) ) {
    FD_LOG_WARNING(( "Stream map full" ));
    fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );

    return NULL;
  }

  entry->stream = stream;

  /* update metrics */
  quic->metrics.stream_opened_cnt[ next_stream_id&0x3 ]++;
  quic->metrics.stream_active_cnt[ next_stream_id&0x3 ]++;

  return stream;
}

int
fd_quic_stream_send( fd_quic_stream_t *  stream,
                     fd_aio_pkt_info_t * batch,
                     ulong               batch_sz,
                     int                 fin ) {
  if( FD_UNLIKELY( stream->state & FD_QUIC_STREAM_STATE_TX_FIN ) )
    return FD_QUIC_SEND_ERR_STREAM_FIN;

  fd_quic_conn_t * conn = stream->conn;

  fd_quic_buffer_t * tx_buf = &stream->tx_buf;

  /* are we allowed to send? */
  ulong stream_id = stream->stream_id;

  /* stream_id & 2 == 0 is bidir
     stream_id & 1 == 0 is client */
  if( FD_UNLIKELY( ( ( (uint)stream_id & 2u ) == 2u ) &
                   ( ( (uint)stream_id & 1u ) != (uint)conn->server ) ) )
    return FD_QUIC_SEND_ERR_INVAL_STREAM;

  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_ACTIVE ) ) {
    if( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE ||
        conn->state == FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) {
      return 1;
    }
    return FD_QUIC_SEND_ERR_INVAL_CONN;
  }

  ulong buffers_queued = 0;

  /* visit each buffer in batch and store in tx_buf if there is sufficient
     space */
  for( ulong j=0; j<batch_sz; ++j ) {
    ulong         data_sz = batch[j].buf_sz;
    uchar const * data    = batch[j].buf;

    if( data_sz > fd_quic_buffer_avail( tx_buf ) )
      break;

    /* store data from data into tx_buf
       this stores, but does not move the head offset */
    fd_quic_buffer_store( tx_buf, data, data_sz );

    /* advance head */
    tx_buf->head += data_sz;

    /* account for buffers sent/queued */
    buffers_queued++;
  }

  /* insert into send list */
  if( !FD_QUIC_STREAM_ACTION( stream ) ) {
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, stream );
  }
  stream->stream_flags   |= FD_QUIC_STREAM_FLAGS_UNSENT; /* we have unsent data */
  stream->upd_pkt_number  = FD_QUIC_PKT_NUM_PENDING;     /* schedule tx */

  /* don't actually set fin flag if we didn't add the last
     byte to the buffer */
  if( fin && buffers_queued==batch_sz ) {
    fd_quic_stream_fin( stream );
  }

  if( batch_sz>0 && buffers_queued==0 ) {
    return 0;
  }

  /* schedule send */
  fd_quic_reschedule_conn( conn, 0 );

  return (int)buffers_queued;
}

void
fd_quic_stream_fin( fd_quic_stream_t * stream ) {
  if( FD_UNLIKELY( stream->state & FD_QUIC_STREAM_STATE_TX_FIN ) ) {
    FD_LOG_WARNING(( "fd_quic_stream_fin: FIN flag already set" ));
    return;
  }

  fd_quic_conn_t * conn = stream->conn;

  /* insert into send list */
  if( !FD_QUIC_STREAM_ACTION( stream ) ) {
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, stream );
  }
  stream->stream_flags   |= FD_QUIC_STREAM_FLAGS_TX_FIN; /* state immediately updated */
  stream->state          |= FD_QUIC_STREAM_STATE_TX_FIN; /* state immediately updated */
  stream->upd_pkt_number  = FD_QUIC_PKT_NUM_PENDING;     /* update to be sent in next packet */

  /* set the last byte */
  fd_quic_buffer_t * tx_buf = &stream->tx_buf;
  stream->tx_last_byte = tx_buf->tail - 1; /* want last byte index */

  /* TODO update metrics */
}

void
fd_quic_conn_set_rx_max_data( fd_quic_conn_t * conn, ulong rx_max_data ) {
  conn->rx_max_data = rx_max_data;
}

void
fd_quic_stream_set_rx_max_stream_data( fd_quic_stream_t * stream, ulong rx_max_stream_data ) {
  stream->rx_max_stream_data = rx_max_stream_data;
}

/* packet processing */

struct fd_quic_pkt {
  fd_eth_hdr_t       eth[1];
  fd_ip4_hdr_t       ip4[1];
  fd_udp_hdr_t       udp[1];

  /* the following are the "current" values only. There may be more QUIC packets
     in a UDP datagram */
  fd_quic_long_hdr_t long_hdr[1];
  ulong              pkt_number;  /* quic packet number currently being decoded/parsed */
  ulong              rcv_time;    /* time packet was received */
  uint               enc_level;   /* encryption level */
  uint               datagram_sz; /* length of the original datagram */
  uint               ack_flag;    /* ORed together: 0-don't ack  1-ack  2-cancel ack */
  uint ping;
# define ACK_FLAG_NOT_RQD 0
# define ACK_FLAG_RQD     1
# define ACK_FLAG_CANCEL  2
};

void
fd_quic_ack_enc_level( fd_quic_conn_t * conn, uint enc_level ) {
  if( FD_LIKELY( enc_level <= conn->peer_enc_level ) ) return;

  /* peer encryption level has increased, so consider all lower levels
     acked */
  conn->peer_enc_level = (uchar)enc_level;

  fd_quic_pkt_meta_pool_t * pool = &conn->pkt_meta_pool;

  for( uint j = 0; j < enc_level; ++j ) {
    fd_quic_pkt_meta_list_t * sent     = &pool->sent[j];
    fd_quic_pkt_meta_t *      pkt_meta = sent->head;
    fd_quic_pkt_meta_t *      prior    = NULL; /* there is no prior, as this is the head */

    while( pkt_meta ) {
      fd_quic_reclaim_pkt_meta( conn, pkt_meta, j );

      /* remove from list */
      fd_quic_pkt_meta_remove( sent, prior, pkt_meta );

      /* put pkt_meta back in free list */
      fd_quic_pkt_meta_deallocate( pool, pkt_meta );

      /* head should have been reclaimed, so fetch new head */
      pkt_meta = pool->sent[j].head;
    }
  }

  /* discard handshake data with lower enc_level */
  /* TODO */
}

int fd_quic_gen_initial_secret_and_keys(
    fd_quic_crypto_suite_t *suite,
    fd_quic_conn_t *conn,
    fd_quic_conn_id_t *orig_dst_conn_id)
{
  /* Initial Packets
     from rfc:
     initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
  uchar const * initial_salt    = FD_QUIC_CRYPTO_V1_INITIAL_SALT;
  ulong         initial_salt_sz = FD_QUIC_CRYPTO_V1_INITIAL_SALT_SZ;

  if (FD_UNLIKELY(fd_quic_gen_initial_secret(
                      &conn->secrets,
                      initial_salt, initial_salt_sz,
                      orig_dst_conn_id->conn_id, orig_dst_conn_id->sz) != FD_QUIC_SUCCESS))
  {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_gen_initial_secret failed" )) );
    return FD_QUIC_FAILED;
    // goto fail_tls_hs;
  }

  if( fd_quic_gen_secrets( &conn->secrets,
                           fd_quic_enc_level_initial_id, /* generate initial secrets */
                           suite->hmac_fn, suite->hash_sz ) != FD_QUIC_SUCCESS ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_gen_secrets failed" )) );
    return FD_QUIC_FAILED;
    // goto fail_tls_hs;
  }

  /* gen initial keys */
  if( FD_UNLIKELY( fd_quic_gen_keys(
      &conn->keys[ fd_quic_enc_level_initial_id ][ 0 ],
      suite,
      conn->secrets.secret   [ fd_quic_enc_level_initial_id ][ 0 ],
      conn->secrets.secret_sz[ fd_quic_enc_level_initial_id ][ 0 ] )
      != FD_QUIC_SUCCESS ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_gen_keys failed" )) );
    return FD_QUIC_FAILED;
    // goto fail_tls_hs;
  }

  /* gen initial keys */
  if( FD_UNLIKELY( fd_quic_gen_keys(
      &conn->keys[ fd_quic_enc_level_initial_id ][ 1 ],
      suite,
      conn->secrets.secret   [ fd_quic_enc_level_initial_id ][ 1 ],
      conn->secrets.secret_sz[ fd_quic_enc_level_initial_id ][ 1 ] )
      != FD_QUIC_SUCCESS ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_gen_keys failed" )) );
    // goto fail_tls_hs;
    return FD_QUIC_FAILED;
  }
  return FD_QUIC_SUCCESS;
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
                           uchar const *             cur_ptr,
                           ulong                     cur_sz ) {
  fd_quic_conn_t * conn = *p_conn;

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Initial packets are de-facto unencrypted.  Packet protection is
     still applied, albeit with publicly known encryption keys.

     RFC 9001 specifies use of the TLS_AES_128_GCM_SHA256_ID suite for
     initial secrets and keys. */

  uint enc_level = fd_quic_enc_level_initial_id;
  fd_quic_crypto_suite_t * suite =
      &state->crypto_ctx->suites[ TLS_AES_128_GCM_SHA256_ID ];

  /* Save the original destination conn ID for later.  In QUIC, peers
     choose their own "conn ID" (more like a peer ID) and indirectly
     instruct the other peer to be addressed as such via the dest conn
     ID field.  However, when the client sends the first packet, it
     doesn't know the preferred dest conn ID to pick for the server
     Thus, the client picks a random dest conn ID -- which is referred
     to as "original dest conn ID". */

  fd_quic_conn_id_t orig_dst_conn_id = *conn_id;

  /* Parse initial packet */

  fd_quic_initial_t initial[1];
  ulong rc = fd_quic_decode_initial( initial, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;

  /* check bounds on initial */

  /* len indicated the number of bytes after the packet number offset
     so verify this value is within the packet */
  ulong len = (ulong)( initial->pkt_num_pnoff + initial->len );
  if( FD_UNLIKELY( len > cur_sz ) ) return FD_QUIC_PARSE_FAIL;

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
  if ( FD_UNLIKELY( initial->token_len > 0 &&
                    ( quic->config.role == FD_QUIC_ROLE_CLIENT || !quic->config.retry ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* Initial packets have explicitly encoded conn ID lengths. */

  if( FD_UNLIKELY( ( initial->src_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) |
                   ( initial->dst_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) ) ) {
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
        /* FIXME Arguably no need to inform client of misbehavior */
        return FD_QUIC_PARSE_FAIL;
      }

      /* Early check: Is conn free? */

      if( !state->conns ) {
        FD_DEBUG( FD_LOG_DEBUG(( "ignoring conn request: no free conn slots" )) );
        quic->metrics.conn_err_no_slots_cnt++;
        return FD_QUIC_PARSE_FAIL; /* FIXME better error code? */
      }

      /* Pick a new conn ID for ourselves, which the peer will address us
         with in the future (via dest conn ID). */

      fd_quic_conn_id_t new_conn_id = {8u,{0},{0}};

      fd_quic_crypto_rand( new_conn_id.conn_id, 8u );

      /* Save peer's conn ID, which we will use to address peer with. */

      fd_quic_conn_id_t peer_conn_id = {0};

      fd_memcpy( peer_conn_id.conn_id, initial->src_conn_id, initial->src_conn_id_len );
      peer_conn_id.sz = initial->src_conn_id_len;

      /* Save peer's network endpoint */

      uchar  dst_mac_addr_u6[6] = {0};
      uint   dst_ip_addr        = FD_LOAD( uint, pkt->ip4->saddr_c );
      ushort dst_udp_port       = pkt->udp->net_sport;

      /* Do route and arp query. If these fail, assume the source mac
         works, which will be true in symmetric setups */
      uchar  arp_mac_addr[6]  = {0};
      uint   arp_next_ip_addr = 0;
      uint   arp_ifindex      = 0;
      uint   arp_host_dst_ip  = fd_uint_bswap( dst_ip_addr );
      int arp_rtn = fd_ip_route_ip_addr( arp_mac_addr,
                                         &arp_next_ip_addr,
                                         &arp_ifindex,
                                         fd_quic_get_ip( quic ),
                                         arp_host_dst_ip );
      if( arp_rtn == FD_IP_SUCCESS ) {
        memcpy( dst_mac_addr_u6, arp_mac_addr, 6 );
      } else {
        memcpy( dst_mac_addr_u6, pkt->eth->src, 6 );
      }

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
        FD_LOG_WARNING(( "Unsupported version reached fd_quic_handle_v1_initial" ));
        return FD_QUIC_PARSE_FAIL;
      }

      /* Prepare QUIC-TLS transport params object (sent as a TLS extension).
         Take template from state and mutate certain params in-place.

         See RFC 9000 Section 18 */

      /* TODO Each transport param is a TLV tuple. This allows serializing
         most transport params ahead of time.  Only the conn-specific
         differences will have to be appended here. */

      fd_quic_transport_params_t * tp = &state->transport_params;

      /* Send orig conn ID back to client (server only) */

      tp->original_destination_connection_id_present = 1;
      tp->original_destination_connection_id_len     = orig_dst_conn_id.sz;
      fd_memcpy( state->transport_params.original_destination_connection_id,
          orig_dst_conn_id.conn_id,
          orig_dst_conn_id.sz );

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
          new_conn_id.sz );

      /* Handle retry if configured. */
      if (quic->config.retry)
      {
        /* This is the initial packet before retry. */
        if (initial->token_len == 0)
        {
          /* Set the retry_source_connection_id tp. The server response to the post-retry initial
             will be another SCID. */
          tp->retry_source_connection_id_present = 1;
          tp->retry_source_connection_id_len = new_conn_id.sz;
          fd_memcpy(tp->retry_source_connection_id,
                 new_conn_id.conn_id,
                 new_conn_id.sz);

          fd_quic_retry_t retry_pkt = {
            .hdr_form = 1,
            .fixed_bit = 1,
            // .long_packet_type (initialized below)
            .unused = 0xf,
            .version = 1,
            .dst_conn_id_len = pkt->long_hdr->src_conn_id_len,
            // .dst_conn_id (initialized below)
            .src_conn_id_len = new_conn_id.sz,
            // .src_conn_id (initialized below)
            // .retry_token (initialized below)
            // .retry_integrity_tag (initialized below)
          };

          fd_memcpy(
              retry_pkt.dst_conn_id, pkt->long_hdr->src_conn_id, pkt->long_hdr->src_conn_id_len
          );
          fd_memcpy( retry_pkt.src_conn_id, &new_conn_id.conn_id, retry_pkt.src_conn_id_len );

          /* copy to avoid alignment issues */
          uint saddr = 0;
          memcpy( &saddr, pkt->ip4->saddr_c, 4 );

          /* Retry token */
          ulong now = fd_quic_now(quic);
          int   rc  = fd_quic_retry_token_encrypt(
              &orig_dst_conn_id,
              now,
              &new_conn_id,
              saddr,
              pkt->udp->net_sport,
              retry_pkt.retry_token
          );
          if( FD_UNLIKELY( rc == FD_QUIC_FAILED ) ) {
            quic->metrics.conn_err_retry_fail_cnt++;
            return FD_QUIC_PARSE_FAIL;
          }

          /* Retry integrity tag */
          fd_quic_retry_pseudo_t retry_pseudo_pkt = {
              .odcid_len = orig_dst_conn_id.sz,
              // .odcid
              .hdr_form = retry_pkt.hdr_form,
              .fixed_bit = retry_pkt.fixed_bit,
              .long_packet_type = retry_pkt.long_packet_type,
              .unused = retry_pkt.unused,
              .version = retry_pkt.version,
              .dst_conn_id_len = retry_pkt.dst_conn_id_len,
              // .dst_conn_id
              .src_conn_id_len = retry_pkt.src_conn_id_len,
              // .src_conn_id
              // .retry_token
          };
          // TODO can make this more efficient by directly manipulating the retry_pkt pkt
          // bytes directly: prepending the ODCID and removing the retry_pkt integrity tag

          // TODO zero-copy?
          memcpy( &retry_pseudo_pkt.odcid, &orig_dst_conn_id.conn_id, orig_dst_conn_id.sz );
          memcpy( &retry_pseudo_pkt.dst_conn_id, &retry_pkt.dst_conn_id, retry_pkt.dst_conn_id_len );
          memcpy( &retry_pseudo_pkt.src_conn_id, &retry_pkt.src_conn_id, retry_pkt.src_conn_id_len );
          memcpy( &retry_pseudo_pkt.retry_token, &retry_pkt.retry_token, FD_QUIC_RETRY_TOKEN_SZ );

          ulong retry_pseudo_footprint = fd_quic_encode_footprint_retry_pseudo( &retry_pseudo_pkt );

          uchar retry_pseudo_buf[FD_QUIC_MAX_FOOTPRINT(retry_pseudo)];
          if( FD_UNLIKELY( retry_pseudo_footprint > sizeof(retry_pseudo_buf) ) ) {
            return FD_QUIC_PARSE_FAIL;
          }
          fd_quic_encode_retry_pseudo( retry_pseudo_buf, retry_pseudo_footprint, &retry_pseudo_pkt );
          fd_quic_retry_integrity_tag_encrypt( retry_pseudo_buf, (int) retry_pseudo_footprint, retry_pkt.retry_integrity_tag );

          ulong tx_buf_sz = fd_quic_encode_footprint_retry( &retry_pkt );
          uchar tx_buf[tx_buf_sz];
          fd_quic_encode_retry( tx_buf, tx_buf_sz, &retry_pkt );
          uchar * tx_ptr  = tx_buf + tx_buf_sz;
          ulong   tx_sz   = 0;  // no space remaining after encoding
          uchar   encode_buf[2048];  // space for lower-layer headers, same size as crypt_scratch
          if( FD_UNLIKELY( fd_quic_tx_buffered_raw(
                quic,
                // these are state variable's normally updated on a conn, but irrelevant in retry so we
                // just size it exactly as the encoded retry packet
                &tx_ptr,
                tx_buf,
                tx_buf_sz,
                &tx_sz,
                // encode buffer
                encode_buf,
                sizeof( encode_buf ),
                dst_mac_addr_u6,
                &pkt->ip4->net_id,
                dst_ip_addr,
                quic->config.net.listen_udp_port,
                dst_udp_port,
                1 ) == FD_QUIC_FAILED ) ) {
            quic->metrics.conn_err_retry_fail_cnt++;
            return FD_QUIC_PARSE_FAIL;
          };
          return (initial->pkt_num_pnoff + initial->len);
        }

        /* Otherwise this is the initial packet _after_ retry, i.e. the client's response to retry
           (which is also an initial packet). */
        if( FD_UNLIKELY( initial->token_len != FD_QUIC_RETRY_TOKEN_SZ ) ) {
          quic->metrics.conn_err_retry_fail_cnt++;
          /* No need to set conn error, no conn object exists */
          return FD_QUIC_PARSE_FAIL;
        }

        /* Validate the relevant fields of this post-retry INITIAL packet,
           i.e. retry src conn id, ip, port */
        fd_quic_conn_id_t retry_src_conn_id;
        retry_src_conn_id.sz = initial->dst_conn_id_len;
        fd_memcpy(&retry_src_conn_id.conn_id, initial->dst_conn_id, initial->dst_conn_id_len);

        fd_quic_conn_id_t retry_odcid;
        ulong issued;
        if (FD_UNLIKELY(fd_quic_retry_token_decrypt((uchar *) initial->token, &retry_src_conn_id, dst_ip_addr, dst_udp_port, &retry_odcid, &issued))) {
          quic->metrics.conn_err_retry_fail_cnt++;
          /* No need to set conn error, no conn object exists */
          return FD_QUIC_PARSE_FAIL;
        };
        tp->original_destination_connection_id_len     = retry_odcid.sz;
        fd_memcpy( state->transport_params.original_destination_connection_id,
          retry_odcid.conn_id,
          retry_odcid.sz );
        ulong now = fd_quic_now(quic);
        if ( FD_UNLIKELY( now < issued || ( now - issued ) > FD_QUIC_RETRY_TOKEN_LIFETIME ) ) {
          quic->metrics.conn_err_retry_fail_cnt++;
          /* No need to set conn error, no conn object exists */
          return FD_QUIC_PARSE_FAIL;
        }
        quic->metrics.conn_retry_cnt++;
      }

      /* Allocate new conn */

      conn = fd_quic_conn_create( quic,
          &new_conn_id,  /* our_conn_id */
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

      /* insert into connection map at orig_dst_conn_id */
      fd_quic_conn_entry_t * insert_entry =
        fd_quic_conn_map_insert( state->conn_map, &orig_dst_conn_id );

      /* if insert failed (should be impossible) fail, and do not remove connection
         from free list */
      if( FD_UNLIKELY( insert_entry == NULL ) ) {
        FD_LOG_WARNING(( "fd_quic_conn_create failed: failed to register new conn ID" ));
        fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
        return FD_QUIC_PARSE_FAIL;
      }

      /* set connection map insert_entry to new connection */
      insert_entry->conn = conn;

      /* keep orig_dst_conn_id */

      memcpy( &conn->orig_dst_conn_id, &orig_dst_conn_id, sizeof( orig_dst_conn_id ) );


      /* set the value for the caller */
      *p_conn = conn;

      /* if we fail after here, we must reap the connection
         TODO maybe actually set the connection to reset, and clean up resources later */

      /* Encode transport params to be sent to peer */

      uchar transport_params_raw[ FD_QUIC_TRANSPORT_PARAMS_RAW_SZ ];
      ulong tp_rc = fd_quic_encode_transport_params(
          transport_params_raw,
          FD_QUIC_TRANSPORT_PARAMS_RAW_SZ,
          tp );
      if( FD_UNLIKELY( tp_rc == FD_QUIC_ENCODE_FAIL ) ) {
        /* FIXME log error in counters */
        fd_quic_conn_close(conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR);
        return FD_QUIC_PARSE_FAIL;
      }
      ulong transport_params_raw_sz = tp_rc;

      /* Create a TLS handshake */

      fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
          state->tls,
          (void*)conn,
          1 /*is_server*/,
          quic->config.sni,
          transport_params_raw,
          transport_params_raw_sz );
      if( !tls_hs ) {
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        quic->metrics.conn_aborted_cnt++;
        quic->metrics.hs_err_alloc_fail_cnt++;
        FD_DEBUG( FD_LOG_WARNING(( "fd_quic_tls_hs_new failed" )) );
        return FD_QUIC_PARSE_FAIL;
      }
      conn->tls_hs = tls_hs;

      if (FD_UNLIKELY(fd_quic_gen_initial_secret_and_keys(suite, conn, &orig_dst_conn_id)) == FD_QUIC_FAILED) {
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        quic->metrics.conn_aborted_cnt++;
        quic->metrics.conn_err_tls_fail_cnt++;
        FD_DEBUG( FD_LOG_WARNING(( "fd_quic_gen_initial_secret_and_keys failed" )) );
        return FD_QUIC_PARSE_FAIL;
      }
    } else {
      /* connection may have been torn down */
      return FD_QUIC_PARSE_FAIL;
    }
  }

  /* Decrypt incoming packet */

  /* header protection needs the offset to the packet number */
  ulong   pn_offset        = initial->pkt_num_pnoff;

  uchar * crypt_scratch    = conn->crypt_scratch;
  ulong   crypt_scratch_sz = sizeof( conn->crypt_scratch );

  ulong   body_sz          = initial->len;  /* not a protected field */
                                             /* length of payload + num packet bytes */
  uchar * dec_hdr          = conn->crypt_scratch;
  ulong   dec_hdr_sz       = sizeof( conn->crypt_scratch );

  ulong   pkt_number       = (ulong)-1;
  ulong   pkt_number_sz    = (ulong)-1;
  ulong   tot_sz           = (ulong)-1;

#ifdef FD_QUIC_TEST_INSECURE
  /* testing/sanitizing code */
  uchar zeros[16] = {0};
  if( memcmp( cur_ptr + cur_sz - 16, zeros, 16 ) == 0 ) {
    /* TEST: not encrypted */
    uint          first         = cur_ptr[0];
    /* */         pkt_number_sz = ( first & 0x03u ) + 1u;
    /* */         tot_sz        = pn_offset + body_sz; /* total including header and payload */

    fd_memcpy( conn->crypt_scratch, cur_ptr, cur_sz );

    pkt_number        = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;
  } else {
#endif
    /* this decrypts the header */
    int server = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* As this is an INITIAL packet, change the status to DEAD, and allow
         it to be reaped */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt_hdr failed" )) );
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* number of bytes in the packet header */
    pkt_number_sz = ( (uint)dec_hdr[0] & 0x03u ) + 1u;
    tot_sz        = pn_offset + body_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    pkt_number = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );
    FD_DEBUG( FD_LOG_DEBUG(( "initial pkt_number: %lu", (ulong)pkt_number )) );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* NOTE from rfc9002 s3
       It is permitted for some packet numbers to never be used, leaving intentional gaps. */
    /* this decrypts the header and payload */
    if( fd_quic_crypto_decrypt( crypt_scratch, &crypt_scratch_sz,
                                cur_ptr, tot_sz,
                                pn_offset,
                                pkt_number,
                                suite,
                                &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }
#ifdef FD_QUIC_TEST_INSECURE
  }
#endif

  /* check if reply conn id needs to change */
  if( !( conn->server | conn->established ) ) {
    /* switch to the source connection id for future replies */

    /* replace peer 0 connection id */
    conn->peer[0].conn_id.sz = initial->src_conn_id_len;

    /* we have already validated src_conn_id_len */
    fd_memcpy( conn->peer[0].conn_id.conn_id, initial->src_conn_id, initial->src_conn_id_len );

    /* don't repeat this procedure */
    conn->established = 1;
  }

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = crypt_scratch + payload_off;
  ulong         frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, &conn->frame_union );
    if( rc == FD_QUIC_PARSE_FAIL ) {
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc > frame_sz ) ) {
      fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame, and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = fd_quic_now( quic );

  /* update expected packet number */
  do {
    /* make pn_space local to this code segment due to FD_QUIC_TEST_INSECURE */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    conn->exp_pkt_number[pn_space] = pkt_number + 1u;
  } while(0);

  FD_DEBUG( FD_LOG_DEBUG(( "new connection success" )) );

  /* insert into service queue */
  fd_quic_reschedule_conn( conn, 0 );

  /* return number of bytes consumed */
  return tot_sz;
}

ulong
fd_quic_handle_v1_handshake(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t *       pkt,
    uchar const *         cur_ptr,
    ulong                 cur_sz ) {
  uint enc_level = fd_quic_enc_level_handshake_id;
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;

  if( !conn ) {
    /* this can happen */
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

  /* connection ids should already be in the relevant structures */

  /* TODO prepare most of the transport parameters, and only append the
     necessary differences */

  /* fetch TLS handshake */
  fd_quic_tls_hs_t * tls_hs = conn->tls_hs;
  if( FD_UNLIKELY( !tls_hs ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "no tls handshake" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* generate handshake secrets, keys etc */

  /* fetch suite from connection - should be set via callback fd_quic_tls_cb_secret
     from tls */
  fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

  /* check our suite has been chosen */
  if( FD_UNLIKELY( !suite ) ) {
    FD_LOG_WARNING(( "suite missing" ));
    return FD_QUIC_PARSE_FAIL;
  }

  /* decryption */

  /* header protection needs the offset to the packet number */
  ulong    pn_offset        = handshake->pkt_num_pnoff;

  uchar *  crypt_scratch    = conn->crypt_scratch;
  ulong    crypt_scratch_sz = sizeof( conn->crypt_scratch );

  ulong    body_sz          = handshake->len;  /* not a protected field */
                                               /* length of payload + num packet bytes */
  uchar *  dec_hdr          = conn->crypt_scratch;
  ulong    dec_hdr_sz       = sizeof( conn->crypt_scratch );

  ulong    pkt_number       = (ulong)-1;
  ulong    pkt_number_sz    = (ulong)-1;
  ulong    tot_sz           = (ulong)-1;

#ifdef FD_QUIC_TEST_INSECURE
  /* testing/sanitizing code */
  uchar zeros[16] = {0};
  if( memcmp( cur_ptr + cur_sz - 16, zeros, 16 ) == 0 ) {
    /* TEST: not encrypted */
    uint          first         = cur_ptr[0];
    /* */         pkt_number_sz = ( first & 0x03u ) + 1u;
    /* */         tot_sz        = pn_offset + body_sz; /* total including header and payload */

    fd_memcpy( conn->crypt_scratch, cur_ptr, cur_sz );

    pkt_number        = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;
  } else {
#endif

    /* this decrypts the header */
    int server    = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt_hdr failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* number of bytes in the packet header */
    pkt_number_sz = ( (uint)dec_hdr[0] & 0x03u ) + 1u;
    tot_sz        = pn_offset + body_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    /* TODO packet number processing */
    pkt_number = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* NOTE from rfc9002 s3
      It is permitted for some packet numbers to never be used, leaving intentional gaps. */

    /* this decrypts the header and payload */
    if( fd_quic_crypto_decrypt( crypt_scratch, &crypt_scratch_sz,
                                cur_ptr, tot_sz,
                                pn_offset,
                                pkt_number,
                                suite,
                                &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }
#ifdef FD_QUIC_TEST_INSECURE
  }
#endif

  /* check body size large enough for required elements */
  if( FD_UNLIKELY( body_sz < pkt_number_sz + FD_QUIC_CRYPTO_TAG_SZ ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* if peer encryption level increases, consider prior encryption
     level pkt_meta acked */
  fd_quic_ack_enc_level( conn, enc_level );

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = crypt_scratch + payload_off;
  ulong         frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, &conn->frame_union );
    if( rc == FD_QUIC_PARSE_FAIL ) {
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc > frame_sz ) ) {
      fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = fd_quic_now( quic );

  /* update expected packet number */
  do {
    /* make pn_space local to this code segment due to FD_QUIC_TEST_INSECURE */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    conn->exp_pkt_number[pn_space] = pkt_number + 1u;
  } while(0);

  /* return number of bytes consumed */
  return tot_sz;
}

ulong fd_quic_handle_v1_retry(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t const * pkt,
    uchar const *         cur_ptr,
    ulong                 cur_sz
) {
  (void)pkt;
  if ( FD_UNLIKELY ( quic->config.role == FD_QUIC_ROLE_SERVER ) ) {
    if ( FD_UNLIKELY( conn ) ) { /* likely a misbehaving client w/o a conn */
      fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
    }
    return FD_QUIC_PARSE_FAIL;
  }
  fd_quic_retry_t retry_pkt = {0};
  ulong decode_rc = fd_quic_decode_retry( &retry_pkt, cur_ptr, cur_sz );
  if( FD_UNLIKELY( decode_rc == FD_QUIC_PARSE_FAIL ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  fd_quic_conn_id_t * orig_dst_conn_id = &conn->peer->conn_id;

  /* Validate the Retry Integrity Tag. TODO can we make this more efficient? */
  fd_quic_retry_pseudo_t retry_pseudo_pkt = {
      .odcid_len        = orig_dst_conn_id->sz,
      // .odcid
      .hdr_form         = retry_pkt.hdr_form,
      .fixed_bit        = retry_pkt.fixed_bit,
      .long_packet_type = retry_pkt.long_packet_type,
      .unused           = retry_pkt.unused,
      .version          = retry_pkt.version,
      .dst_conn_id_len  = retry_pkt.dst_conn_id_len,
      // .dst_conn_id
      .src_conn_id_len  = retry_pkt.src_conn_id_len,
      // .src_conn_id
      // .retry_token
  };

  /* Retry-pseudo packet is the retry packet with ODCID prepended and integrity
     tag removed*/
  fd_memcpy( retry_pseudo_pkt.odcid, orig_dst_conn_id->conn_id, orig_dst_conn_id->sz );
  fd_memcpy( retry_pseudo_pkt.dst_conn_id, retry_pkt.dst_conn_id, retry_pkt.dst_conn_id_len );
  fd_memcpy( retry_pseudo_pkt.src_conn_id, retry_pkt.src_conn_id, retry_pkt.src_conn_id_len );
  memcpy( retry_pseudo_pkt.retry_token, retry_pkt.retry_token, FD_QUIC_RETRY_TOKEN_SZ );

  ulong retry_pseudo_footprint = fd_quic_encode_footprint_retry_pseudo( &retry_pseudo_pkt );
  uchar retry_pseudo_buf[retry_pseudo_footprint];
  fd_quic_encode_retry_pseudo( retry_pseudo_buf, retry_pseudo_footprint, &retry_pseudo_pkt );

  /* Validate the retry integrity tag

     Retry packets (see Section 17.2.5 of [QUIC-TRANSPORT]) carry a Retry Integrity Tag that
     provides two properties: it allows the discarding of packets that have accidentally been
     corrupted by the network, and only an entity that observes an Initial packet can send a valid
     Retry packet.*/
  int rc = fd_quic_retry_integrity_tag_decrypt(
      retry_pseudo_buf, (int)retry_pseudo_footprint, retry_pkt.retry_integrity_tag
  );

  /* Clients MUST discard Retry packets that have a Retry Integrity Tag that
     cannot be validated */

  if ( FD_UNLIKELY( rc == FD_QUIC_FAILED ) ) {
    return cur_sz;  // FIXME hack to drop packet
  }

  /* Update the peer using the retry src conn id */
  fd_quic_endpoint_t * peer         = &conn->peer[conn->cur_peer_idx];
  peer->conn_id.sz = retry_pkt.src_conn_id_len;
  fd_memcpy( peer->conn_id.conn_id, retry_pkt.src_conn_id, retry_pkt.src_conn_id_len );

  /* Re-send the ClientHello */
  conn->hs_sent_bytes[fd_quic_enc_level_initial_id] = 0;
  fd_quic_state_t *state = fd_quic_get_state(quic);

  /* Need to regenerate keys using the retry source connection id */
  fd_quic_crypto_suite_t *suite = &state->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];
  fd_quic_conn_id_t retry_src_conn_id;
  retry_src_conn_id.sz = retry_pkt.src_conn_id_len;
  fd_memcpy(&retry_src_conn_id.conn_id, &retry_pkt.src_conn_id, retry_pkt.src_conn_id_len);
  if (FD_UNLIKELY(fd_quic_gen_initial_secret_and_keys(suite, conn, &retry_src_conn_id)) == FD_QUIC_FAILED)
  {
    conn->state = FD_QUIC_CONN_STATE_DEAD;
    quic->metrics.conn_aborted_cnt++;
    quic->metrics.conn_err_tls_fail_cnt++;
    return FD_QUIC_PARSE_FAIL;
  }
  /* The token length is the remaining bytes in the retry packet after subtracting known fields. */
  conn->token_len = cur_sz - FD_QUIC_EMPTY_RETRY_PKT_SZ - retry_pkt.src_conn_id_len - retry_pkt.dst_conn_id_len;
  fd_memcpy(&conn->token, retry_pkt.retry_token, conn->token_len);

  return cur_sz;
}

ulong
fd_quic_handle_v1_zero_rtt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t const * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;
  FD_DEBUG( FD_LOG_DEBUG(( "stub" )) );
  /* since we do not support zero-rtt, simply fail the packet */
  return FD_QUIC_PARSE_FAIL;
}

ulong
fd_quic_handle_v1_one_rtt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  if( !conn ) {
    /* this can happen */
    return FD_QUIC_PARSE_FAIL;
  }

  /* encryption level for one_rtt is "appdata" */
  uint enc_level = fd_quic_enc_level_appdata_id;

  /* set on pkt for future processing */
  pkt->enc_level = enc_level;

  fd_quic_one_rtt_t one_rtt[1];

  /* hidden field needed by decode function */
  one_rtt->dst_conn_id_len = 8;

  ulong rc = fd_quic_decode_one_rtt( one_rtt, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_one_rtt failed" )) );
    return FD_QUIC_PARSE_FAIL;
  }

  /* generate one_rtt secrets, keys etc */

  /* fetch suite from connection - should be set via callback fd_quic_tls_cb_secret
     from tls */
  fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

  /* check our suite has been chosen */
  if( FD_UNLIKELY( !suite ) ) {
    FD_LOG_WARNING(( "suite missing" ));
    return FD_QUIC_PARSE_FAIL;
  }

  /* decryption */

  /* header protection needs the offset to the packet number */
  ulong    pn_offset        = one_rtt->pkt_num_pnoff;

  uchar *  crypt_scratch    = conn->crypt_scratch;
  ulong    crypt_scratch_sz = sizeof( conn->crypt_scratch );

  uchar *  dec_hdr          = conn->crypt_scratch;
  ulong    dec_hdr_sz       = sizeof( conn->crypt_scratch );

  ulong    pkt_number       = (ulong)-1;
  ulong    pkt_number_sz    = (ulong)-1;
  ulong    tot_sz           = (ulong)-1;

#ifdef FD_QUIC_TEST_INSECURE
  /* testing/sanitizing code */
  uchar zeros[16] = {0};
  if( memcmp( cur_ptr + cur_sz - 16, zeros, 16 ) == 0 ) {
    /* TEST: not encrypted */
    fd_memcpy( conn->crypt_scratch, cur_ptr, cur_sz );

    pkt_number_sz     = ( (uint)dec_hdr[0] & 0x03u ) + 1u;
    tot_sz            = cur_sz;

    pkt_number        = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* since the packet number is greater than the highest last seen,
       do spin bit processing */
    /* TODO by spec 1 in 16 connections should have this disabled */
    uint spin_bit = (uint)dec_hdr[0] & (1u << 2u);
    conn->spin_bit = (uchar)( spin_bit ^ ( (uint)conn->server ^ 1u ) );

  } else {
#endif

    /* this decrypts the header */
    int server = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt_hdr failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* get first byte for future use */
    uint first = (uint)dec_hdr[0];

    /* number of bytes in the packet header */
    pkt_number_sz = ( first & 0x03u ) + 1u;
    tot_sz        = cur_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    /* TODO packet number processing */
    pkt_number = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );
    FD_DEBUG( FD_LOG_DEBUG(( "one_rtt pkt_number: %lu", pkt_number )) );

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* since the packet number is greater than the highest last seen,
       do spin bit processing */
    /* TODO by spec 1 in 16 connections should have this disabled */
    uint spin_bit = first & (1u << 6u);
    conn->spin_bit = (uchar)( spin_bit ^ ( (uint)conn->server ^ 1u ) );

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
      FD_LOG_DEBUG(( "key update started" ));

      /* generate new secrets */
      if( fd_quic_gen_new_secrets( &conn->secrets, suite->hmac_fn, suite->hash_sz ) != FD_QUIC_SUCCESS ) {
        FD_LOG_WARNING(( "Unable to generate new secrets for key update. "
              "Aborting connection" ));
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
        return FD_QUIC_PARSE_FAIL;
      }

      /* generate new keys */
      if( FD_UNLIKELY( fd_quic_gen_new_keys( &conn->new_keys[0],
                                             suite,
                                             conn->secrets.new_secret[0],
                                             conn->secrets.secret_sz[enc_level][0],
                                             suite->hmac_fn, suite->hash_sz )
            != FD_QUIC_SUCCESS ) ) {
        /* set state to DEAD to reclaim connection */
        FD_LOG_WARNING(( "fd_quic_gen_keys failed on client" ));
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
        return FD_QUIC_PARSE_FAIL;
      }
      if( FD_UNLIKELY( fd_quic_gen_new_keys( &conn->new_keys[1],
                                             suite,
                                             conn->secrets.new_secret[1],
                                             conn->secrets.secret_sz[enc_level][1],
                                             suite->hmac_fn, suite->hash_sz )
            != FD_QUIC_SUCCESS ) ) {
        /* set state to DEAD to reclaim connection */
        FD_LOG_WARNING(( "fd_quic_gen_keys failed on server" ));
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
        return FD_QUIC_PARSE_FAIL;
      }

      conn->key_phase_upd = 1;
    }

    fd_quic_crypto_keys_t * keys = current_key_phase ? &conn->keys[enc_level][!server]
                                                     : &conn->new_keys[!server];

    /* this decrypts the header and payload */
    if( fd_quic_crypto_decrypt( crypt_scratch, &crypt_scratch_sz,
                                cur_ptr, tot_sz,
                                pn_offset,
                                pkt_number,
                                suite,
                                keys ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_crypto_decrypt failed" )) );
      quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_PARSE_FAIL;
    }
#ifdef FD_QUIC_TEST_INSECURE
  }
#endif

  /* if peer encryption level increases, consider prior encryption
     level pkt_meta acked */
  fd_quic_ack_enc_level( conn, enc_level );

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = crypt_scratch + payload_off;
  ulong         frame_sz    = cur_sz - pn_offset - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz != 0UL ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, &conn->frame_union );
    if( rc == FD_QUIC_PARSE_FAIL ) {
      return FD_QUIC_PARSE_FAIL;
    }

    if( FD_UNLIKELY( rc > frame_sz ) ) {
      fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    /* next frame, and remaining size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* update last activity */
  conn->last_activity = fd_quic_now( quic );

  /* update expected packet number */
  do {
    /* make pn_space local to this code segment due to FD_QUIC_TEST_INSECURE */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );
    conn->exp_pkt_number[pn_space] = pkt_number + 1u;
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

  timeout = fd_ulong_max( timeout, fd_quic_now(quic) + 1UL );

  /* insert key */
  fd_quic_event_t event[1] = {{ .timeout = timeout, .conn = conn }};
  service_queue_insert( state->service_queue, event );

  conn->sched_service_time = timeout;
  conn->next_service_time  = timeout;
  conn->in_service         = 1;
}

/* get the service interval, while ensuring the value
   is sufficient */
ulong
fd_quic_get_service_interval( fd_quic_t * quic ) {
  ulong min_service_interval = (ulong)10e6;
  ulong service_interval = quic->config.service_interval;
  if( FD_UNLIKELY( service_interval < min_service_interval ) ) {
    service_interval = quic->config.service_interval = min_service_interval;
  }
  return service_interval;
}

void
fd_quic_reschedule_conn( fd_quic_conn_t * conn,
                         ulong            timeout ) {
  fd_quic_t *       quic  = conn->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong now = fd_quic_now(quic);

  ulong service_interval = fd_quic_get_service_interval( quic );

  timeout = fd_ulong_min( timeout, now + service_interval );
  timeout = fd_ulong_max( timeout, now + 1UL );

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

/* generate acks and add to queue for future tx */
void
fd_quic_ack_pkt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t * pkt ) {
  (void)quic;
  (void)conn;
  uint enc_level = pkt->enc_level;
  uint pn_space  = fd_quic_enc_level_to_pn_space( enc_level );
  (void)enc_level;
  (void)pn_space;

  /* during frame processing acks for that packet may be cancelled */
  if( pkt->ack_flag & ACK_FLAG_CANCEL ) {
    return;
  }

  /* calculate new ack time
     handshakes do not wait
     non-ack-eliciting packets can wait, but not indefinitely */
  ulong now      = fd_quic_now( quic );
  ulong ack_time = now + 1;                 /* initial and handshake ack-eliciting packets
                                             should ack immediately */
  uint ack_mandatory = pkt->ack_flag & ACK_FLAG_RQD;

  /* packet contains ack-eliciting frame */
  if( ack_mandatory ) {
    pkt->ack_flag = 0;
    /* initial and handshake packets get ack'ed immediately */
    if( enc_level != fd_quic_enc_level_initial_id &&
        enc_level != fd_quic_enc_level_handshake_id ) {
      ulong peer_max_ack_delay = fd_ulong_max( 1, conn->peer_max_ack_delay );
      ack_time = now + peer_max_ack_delay; /* TODO subtract rtt? */
    }
  } else {
    /* not ack-eliciting */
    /* if it's been too long, we can send a ping */
    ack_time = now + fd_quic_get_service_interval( quic ); /* randomize */
  }

  /* algo:
     if there exists a last unsent ack, and the last ack refers to the prior packet
       simply extend it
     else
       we need to add a new entry
         allocate new entry
           if none, free old entry, and reuse
           if none, free old entry at another enc level
           if none, horrible bug - die
         if a prior ack refers to the prior packet number
           copy the range into this one, and extend
         insert at end
           so the acks are in increasing order of packet number */
  ulong pkt_number = pkt->pkt_number;
  (void)pkt_number;

  fd_quic_ack_t ** acks_free   = &conn->acks_free;
  fd_quic_ack_t ** acks_tx     = conn->acks_tx     + enc_level;
  fd_quic_ack_t ** acks_tx_end = conn->acks_tx_end + enc_level;

#if 1
  /* if there exists a last ack, and it refers to the prior packet,
     extend it
     range.offset_hi refers the the last offset + 1 */
  fd_quic_ack_t * tail_ack = *acks_tx_end;
  if( pkt_number > 0u && tail_ack && tail_ack->pkt_number.offset_hi == pkt_number ) {
    tail_ack->pkt_number.offset_hi++;

    /* if the calculated ack time is sooner than this ack, update
       and reschedule service */
    if( ack_time < tail_ack->tx_time ) {
      tail_ack->tx_time = ack_time;
    } else {
      ack_time = tail_ack->tx_time;
    }

    /* update packet received time */
    tail_ack->pkt_rcvd  = pkt->rcv_time; /* the time the packet was received */

    fd_quic_reschedule_conn( conn, ack_time );

    /* promote to mandatory, if necessary */
    tail_ack->flags = (uchar)( tail_ack->flags | ( ack_mandatory ? FD_QUIC_ACK_FLAGS_MANDATORY : 0 ) );
    tail_ack->flags = (uchar)( tail_ack->flags & ~FD_QUIC_ACK_FLAGS_SENT );

    return;
  }
#endif

  /* we need to allocate an ack */
  fd_quic_ack_t * ack = *acks_free;

  if( FD_LIKELY( ack ) ) {
    /* move head of free list to next ack */
    *acks_free = ack->next;
    ack->next = NULL;
  } else {
    /* no ack - free an old one */
    /* TODO, when we discard an ack, we must increase a "min_accept_pkt_number" for that pn_space */

    /* iterate thru used acks until end, so we know prior */
    uint tmp_enc_level = enc_level;
    fd_quic_ack_t * cur_ack     = conn->acks_tx    [tmp_enc_level];
    fd_quic_ack_t * last_ack    = conn->acks_tx_end[tmp_enc_level];
    fd_quic_ack_t * prior_ack   = NULL;
    while( cur_ack && cur_ack != last_ack ) {
      prior_ack  = cur_ack;
      cur_ack    = cur_ack->next;
    }

    if( FD_UNLIKELY( !cur_ack ) ) {
      /* find an ack from another enc_level */
      tmp_enc_level = ~0u;

      prior_ack = NULL;
      for( uint j = 0; j < 4; ++j ) {
        cur_ack     = conn->acks_tx    [j];
        last_ack    = conn->acks_tx_end[j];
        if( cur_ack ) {
          tmp_enc_level = j;
          while( cur_ack && cur_ack != last_ack ) {
            prior_ack  = cur_ack;
            cur_ack    = cur_ack->next;
          }
          break;
        }
      }

      if( FD_UNLIKELY( !cur_ack ) ) {
        /* this shouldn't be possible */

        /* terminate the connection, and allow it to be be recycled and
           reinitialized */

        fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
        return;
      }
    }

    /* we should always have a prior */
    if( FD_LIKELY( prior_ack ) ) {
      /* remove from used list */
      prior_ack->next = cur_ack->next;
      cur_ack->next   = NULL;
    } else {
      /* this could occur if only 1 ack is allocated
         -- don't do that */
      /* remove from head */
      conn->acks_tx[tmp_enc_level] = NULL;
    }

    /* use removed */
    ack = cur_ack;
  }

  /* we have an ack, populate and insert at head of appropriate list */
  ack->tx_pkt_number        = FD_QUIC_PKT_NUM_UNUSED; /* unset - indicates we haven't sent the ack yet */
  ack->pkt_number.offset_lo = pkt_number;
  ack->pkt_number.offset_hi = pkt_number + 1u;    /* offset_hi is the next one */
  ack->next                 = *acks_tx;           /* points to head of list for current enc_level */
  ack->enc_level            = (uchar)enc_level;   /* don't really need - it's implied */
  ack->pn_space             = (uchar)pn_space;    /* don't really need - it's implied */
  ack->flags                = ack_mandatory ? FD_QUIC_ACK_FLAGS_MANDATORY : 0u;
  ack->tx_time              = ack_time;
  ack->pkt_rcvd             = pkt->rcv_time;      /* the time the packet was received */

  /* insert at end of list */
  if( *acks_tx_end == NULL ) {
    ack->next    = NULL;
    *acks_tx_end = *acks_tx = ack;
  } else {
    ack->next            = NULL;
    (*acks_tx_end)->next = ack;
    *acks_tx_end         = ack;

    /* if mandatory, check for prior acks with lower priority */
    if( ack_mandatory ) {
      fd_quic_ack_t * cur_ack = *acks_tx;
      while( cur_ack ) {
        cur_ack->flags |= FD_QUIC_ACK_FLAGS_MANDATORY;
        cur_ack->tx_time = fd_ulong_min( cur_ack->tx_time, ack_time );

        /* pretend we haven't sent */
        cur_ack->tx_pkt_number        = FD_QUIC_PKT_NUM_UNUSED;

        cur_ack = cur_ack->next;
      }
    }
  }

  fd_quic_reschedule_conn( conn, ack_time );

}

/* process v1 quic packets
   only called for packets with long header
   returns number of bytes consumed, or FD_QUIC_PARSE_FAIL upon error
   assumes cur_sz >= FD_QUIC_SHORTEST_PKT */
#define FD_QUIC_SHORTEST_PKT 16
ulong
fd_quic_process_quic_packet_v1( fd_quic_t *     quic,
                                fd_quic_pkt_t * pkt,
                                uchar const *   cur_ptr,
                                ulong           cur_sz ) {

  fd_quic_state_t *      state = fd_quic_get_state( quic );
  fd_quic_conn_entry_t * entry = NULL;
  fd_quic_conn_t *       conn  = NULL;

  if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) return FD_QUIC_PARSE_FAIL;

  /* keep end */
  uchar const * orig_ptr = cur_ptr;

  /* extract the dst connection id */
  fd_quic_conn_id_t dst_conn_id = { FD_QUIC_CONN_ID_SZ, {0}, {0} }; /* initialize assuming fixed-length conn id */

  fd_quic_common_hdr_t common_hdr[1];
  ulong rc = fd_quic_decode_common_hdr( common_hdr, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

  /* TODO simplify, as this function only called for long_hdr packets now */
  /* hdr_form is 1 bit */
  if( common_hdr->hdr_form == 1 ) { /* long header */

    fd_quic_long_hdr_t * long_hdr = pkt->long_hdr;
    rc = fd_quic_decode_long_hdr( long_hdr, cur_ptr+1, cur_sz-1 );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    dst_conn_id.sz = long_hdr->dst_conn_id_len;
    if( dst_conn_id.sz > sizeof( dst_conn_id.conn_id ) ) return FD_QUIC_PARSE_FAIL;

    fd_memcpy( &dst_conn_id.conn_id, &long_hdr->dst_conn_id, long_hdr->dst_conn_id_len );

    /* find connection id */
    entry = fd_quic_conn_map_query( state->conn_map, &dst_conn_id );
    conn  = entry ? entry->conn : NULL;

    /* encryption level matches that of TLS */
    pkt->enc_level = common_hdr->long_packet_type; /* V2 uses an indirect mapping */

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* long_packet_type is 2 bits, so only four possibilities */
    switch( common_hdr->long_packet_type ) {
      case FD_QUIC_PKTTYPE_V1_INITIAL:
        rc = fd_quic_handle_v1_initial( quic, &conn, pkt, &dst_conn_id, cur_ptr, cur_sz );
        if( !conn ) return FD_QUIC_PARSE_FAIL;
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

    if( rc == FD_QUIC_PARSE_FAIL ) {
      return FD_QUIC_PARSE_FAIL;
    }

  } else { /* short header */
    /* caller checks cur_sz is sufficient */
    fd_memcpy( &dst_conn_id.conn_id, cur_ptr+1, FD_QUIC_CONN_ID_SZ );

    /* encryption level of short header packets is fd_quic_enc_level_appdata_id */
    pkt->enc_level = fd_quic_enc_level_appdata_id;

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* find connection id */
    entry = fd_quic_conn_map_query( state->conn_map, &dst_conn_id );
    if( !entry ) {
      FD_DEBUG( FD_LOG_DEBUG(( "one_rtt failed: no connection found" )) );
      return FD_QUIC_PARSE_FAIL;
    }

    conn = entry->conn;

    rc = fd_quic_handle_v1_one_rtt( quic, conn, pkt, cur_ptr, cur_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;
  }

  if( rc == 0UL ) {
    /* this is an error because it causes infinite looping */
    return FD_QUIC_PARSE_FAIL;
  }

  /* if we get here we parsed all the frames, so ack the packet */
  if( pkt->pkt_number != FD_QUIC_PKT_NUM_UNUSED ) {
    fd_quic_ack_pkt( quic, conn, pkt );
  }

  cur_ptr += rc;

  /* return bytes consumed */
  return (ulong)( cur_ptr - orig_ptr );
}

void
fd_quic_process_packet( fd_quic_t *   quic,
                        uchar const * data,
                        ulong         data_sz ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong rc = 0;

  /* holds the remainder of the packet*/
  uchar const * cur_ptr = data;
  ulong         cur_sz  = data_sz;

  if( data_sz > 0xffffu ) {
    /* sanity check */
    FD_LOG_WARNING(( "unreasonably large packet received (%lu). Discarding",
                         (ulong)data_sz ));
    return;
  }

  fd_quic_pkt_t pkt = { .datagram_sz = (uint)data_sz };

  pkt.rcv_time = fd_quic_now( quic );

  /* parse eth, ip, udp */
  rc = fd_quic_decode_eth( pkt.eth, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    /* TODO count failure, log-debug failure */
    return;
  }

  /* TODO support for vlan? */

  if( pkt.eth->net_type != FD_ETH_HDR_TYPE_IP ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Invalid ethertype: %4.4x", pkt.eth->net_type )) );
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_ip4( pkt.ip4, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    /* TODO count failure, log-debug failure */
    return;
  }

  /* check version, tot_len, protocol, checksum? */
  if( ( pkt.ip4->protocol != FD_IP4_HDR_PROTOCOL_UDP ) ) {
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_udp( pkt.udp, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    /* TODO count failure, log-debug failure */
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

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
  if( cur_sz < FD_QUIC_SHORTEST_PKT ) {
    return;
  }

#define DECODE_UINT32(p) ( \
    ( (uint)((p)[0]) << (uint)0x18 ) + \
    ( (uint)((p)[1]) << (uint)0x10 ) + \
    ( (uint)((p)[2]) << (uint)0x08 ) + \
    ( (uint)((p)[3]) << (uint)0x00 ) )

  /* check version */

  /* short packets don't have version */
  uint long_pkt = ( (uint)cur_ptr[0] & 0x80u ) >> 7u;

  /* version at offset 1..4 */
  uint version = 0;

  if( long_pkt ) {
    version = DECODE_UINT32( cur_ptr + 1 );

    /* version negotiation packet has version 0 */
    if( version == 0 ) {
       /* TODO implement version negotiation */
      return;
    }

    if( version != 1 ) {
      /* cannot interpret length, so discard entire packet */
      /* TODO send version negotiation */
      return;
    }

    /* 0x?a?a?a?au is intended to force version negotiation
       TODO implement */
    if( ( version & 0x0a0a0a0au ) == 0x0a0a0a0au ) {
      /* at present, ignore */
      return;
    }

    /* multiple QUIC packets in a UDP packet */
    /* shortest valid quic payload? */
    while( cur_sz >= FD_QUIC_SHORTEST_PKT ) {
      /* check version */
      uint cur_version = DECODE_UINT32( cur_ptr + 1 );

      /* version is only in long packets (first byte bit 0 set) */
      if( ( cur_ptr[0] & 0x80u ) && cur_version != version ) {
        /* multiple versions in a single connection is a violation, and by
           extension so is multiple versions in a single udp datagram
           these are silently ignored

           for reference
             all quic packets in a udp datagram must be for the same connection id
               (section 12.2) and therefore the same connection
             all packets on a connection must be of the same version (5.2) */
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
        return;
      }

      if( FD_UNLIKELY( rc > cur_sz ) ) {
        return;
      }

      /* return code (rc) is the number of bytes consumed */
      cur_sz  -= rc;
      cur_ptr += rc;
    }
  } else {
    /* short header packet
       only one_rtt packets currently have short headers */

    /* extract destination connection id to look up connection */
    fd_quic_conn_id_t dst_conn_id = { 8u, {0}, {0} }; /* our connection ids are 8 bytes */
    fd_memcpy( &dst_conn_id.conn_id, cur_ptr+1, FD_QUIC_CONN_ID_SZ );

    /* find connection id */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( state->conn_map, &dst_conn_id );
    if( !entry ) {
      /* silently ignore */
      return;
    }

#if 0
    fd_quic_conn_t * conn  = entry->conn;
    (void)fd_quic_handle_v1_one_rtt( quic, conn, &pkt, cur_ptr, cur_sz );
#else
    (void)fd_quic_process_quic_packet_v1( quic, &pkt, cur_ptr, cur_sz );
#endif
  }
}

/* main receive-side entry point */
int
fd_quic_aio_cb_receive( void *                    context,
                        fd_aio_pkt_info_t const * batch,
                        ulong                     batch_cnt,
                        ulong *                   opt_batch_idx,
                        int                       flush ) {
  (void)flush;

  fd_quic_t * quic = (fd_quic_t*)context;

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

  return FD_AIO_SUCCESS;
}

/* define callbacks from quic-tls into quic */
int
fd_quic_tls_cb_client_hello( fd_quic_tls_hs_t * hs,
                             void *             context ) {
  (void)hs;
  (void)context;
  return FD_QUIC_TLS_SUCCESS; /* accept everything */
}

void
fd_quic_tls_cb_alert( fd_quic_tls_hs_t * hs,
                      void *             context,
                      int                alert ) {
  (void)hs;
  (void)context;
  (void)alert;
  FD_DEBUG( fd_quic_conn_t * conn = (fd_quic_conn_t *)context;
            FD_LOG_DEBUG( ( "TLS : %s\n", conn->server ? "SERVER" : "CLIENT" ) );
            FD_LOG_DEBUG( ( "TLS alert: %d\n", alert ) );
            FD_LOG_DEBUG( ( "TLS CALLBACK: %s\n", __func__ ) );
            FD_LOG_DEBUG( (
                ( "TLS alert: %s %s\n" ),
                SSL_alert_type_string_long( alert ),
                SSL_alert_desc_string_long( alert )
            ) )
            );

  /* may use the following to retrieve alert information:

     SSL_alert_type_string_long( alert )
     SSL_alert_desc_string_long( alert ) */

  /* TODO store alert to reply to peer */
}

void
fd_quic_tls_cb_secret( fd_quic_tls_hs_t *           hs,
                       void *                       context,
                       fd_quic_tls_secret_t const * secret ) {
  (void)hs;
  (void)context;
  (void)secret;

  fd_quic_conn_t *  conn   = (fd_quic_conn_t*)context;
  fd_quic_t *       quic   = conn->quic;
  fd_quic_state_t * state  = fd_quic_get_state( quic );
  int               server = conn->server;

  /* look up suite */
  /* set secrets */
  if( FD_UNLIKELY( secret->enc_level < 0 || secret->enc_level >= FD_QUIC_NUM_ENC_LEVELS ) ) {
    FD_LOG_WARNING(( "callback with invalid encryption level" ));
    return;
  }

  if( FD_UNLIKELY( secret->secret_len > FD_QUIC_MAX_SECRET_SZ ) ) {
    FD_LOG_WARNING(( "callback with invalid secret length" ));
    return;
  }

  uint enc_level = secret->enc_level;

  fd_quic_crypto_secrets_t * crypto_secret = &conn->secrets;

  uchar secret_sz = (uchar)secret->secret_len;
  crypto_secret->secret_sz[enc_level][0] = secret_sz;
  crypto_secret->secret_sz[enc_level][1] = secret_sz;

  fd_memcpy( &crypto_secret->secret[enc_level][!server][0], secret->read_secret,  secret_sz );
  fd_memcpy( &crypto_secret->secret[enc_level][ server][0], secret->write_secret, secret_sz );

  uint suite_id = secret->suite_id;
  uchar major = (uchar)( suite_id >> 8u );
  uchar minor = (uchar)( suite_id );
  int suite_idx = fd_quic_crypto_lookup_suite( major, minor );

  if( suite_idx >= 0 ) {
    fd_quic_crypto_suite_t * suite = conn->suites[enc_level] = &state->crypto_ctx->suites[ suite_idx ];

    /* gen keys */
    if( fd_quic_gen_keys( &conn->keys[enc_level][0],
                          suite,
                          conn->secrets.secret   [ enc_level ][0],
                          conn->secrets.secret_sz[ enc_level ][0] )
          != FD_QUIC_SUCCESS ) {
      /* set state to DEAD to reclaim connection */
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      FD_LOG_WARNING(( "fd_quic_gen_keys failed on client" ));
    }

    /* gen initial keys */
    if( FD_UNLIKELY(
        fd_quic_gen_keys( &conn->keys[enc_level][1],
        suite,
        conn->secrets.secret   [ enc_level ][1],
        conn->secrets.secret_sz[ enc_level ][1] ) ) != FD_QUIC_SUCCESS ) {
      /* set state to DEAD to reclaim connection */
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      FD_LOG_WARNING(( "fd_quic_gen_keys failed on server" ));
    }

  }

}

void
fd_quic_tls_cb_handshake_complete( fd_quic_tls_hs_t * hs,
                                   void *             context ) {
  fd_quic_conn_t * conn = (fd_quic_conn_t*)context;

  /* need to send quic handshake completion */
  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
    case FD_QUIC_CONN_STATE_DEAD:
      /* ignore */
      return;

    case FD_QUIC_CONN_STATE_HANDSHAKE:
      {
        conn->handshake_complete = 1;
        conn->state              = FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE;

        /* handle transport params */
        uchar const * peer_transport_params_raw    = NULL;
        ulong         peer_transport_params_raw_sz = 0;

        fd_quic_tls_get_peer_transport_params( hs,
                                               &peer_transport_params_raw,
                                               &peer_transport_params_raw_sz );

        /* decode peer transport parameters */
        int rc = fd_quic_decode_transport_params( &conn->peer_transport_params,
                                                  peer_transport_params_raw,
                                                  peer_transport_params_raw_sz );
        if( FD_UNLIKELY( rc != 0 ) ) {
          /* failed to parse transport params */
          fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR );
          return;
        }

        /* flow control parameters */
        fd_quic_transport_params_t * peer_tp = &conn->peer_transport_params;
        conn->tx_max_data                            = peer_tp->initial_max_data;
        conn->tx_initial_max_stream_data_uni         = peer_tp->initial_max_stream_data_uni;
        conn->tx_initial_max_stream_data_bidi_local  = peer_tp->initial_max_stream_data_bidi_local;
        conn->tx_initial_max_stream_data_bidi_remote = peer_tp->initial_max_stream_data_bidi_remote;

        fd_quic_state_t * state = fd_quic_get_state( conn->quic );
        fd_quic_transport_params_t * our_tp = &state->transport_params;
        conn->rx_max_data                            = our_tp->initial_max_data;
        conn->rx_initial_max_stream_data_uni         = our_tp->initial_max_stream_data_uni;
        conn->rx_initial_max_stream_data_bidi_local  = our_tp->initial_max_stream_data_bidi_local;
        conn->rx_initial_max_stream_data_bidi_remote = our_tp->initial_max_stream_data_bidi_remote;

        /* max datagram size */
        ulong tx_max_datagram_sz = peer_tp->max_udp_payload_size;
        if( tx_max_datagram_sz < FD_QUIC_INITIAL_PAYLOAD_SZ_MAX ) {
          tx_max_datagram_sz = FD_QUIC_INITIAL_PAYLOAD_SZ_MAX;
        }
        if( tx_max_datagram_sz > FD_QUIC_INITIAL_PAYLOAD_SZ_MAX ) {
          tx_max_datagram_sz = FD_QUIC_INITIAL_PAYLOAD_SZ_MAX;
        }
        conn->tx_max_datagram_sz = (uint)tx_max_datagram_sz;

        /* max streams
           set the initial max allowed by the peer */
        uint stream_cnt = (uint)(
            conn->quic->limits.stream_cnt[ 0x00 ] +
            conn->quic->limits.stream_cnt[ 0x01 ] +
            conn->quic->limits.stream_cnt[ 0x02 ] +
            conn->quic->limits.stream_cnt[ 0x03 ] );
        if( conn->server ) {
          /* 0x01 server-initiated, bidirectional */
          conn->max_streams[0x01] = fd_uint_min( stream_cnt, (uint)peer_tp->initial_max_streams_bidi );
          /* 0x03 server-initiated, unidirectional */
          conn->max_streams[0x03] = fd_uint_min( stream_cnt, (uint)peer_tp->initial_max_streams_uni );
        } else {
          /* 0x00 client-initiated, bidirectional */
          conn->max_streams[0x00] = fd_uint_min( stream_cnt, (uint)peer_tp->initial_max_streams_bidi );
          /* 0x02 client-initiated, unidirectional */
          conn->max_streams[0x02] = fd_uint_min( stream_cnt, (uint)peer_tp->initial_max_streams_uni );
        }

        return;
      }

    default:
      FD_LOG_WARNING(( "%s : handshake in unexpected state: %u", __func__, (uint)conn->state ));
  }
}

void
fd_quic_tls_cb_keylog( fd_quic_tls_hs_t * hs,
                       char const *       line ) {

  fd_quic_conn_t * conn = (fd_quic_conn_t *)hs->context;
  fd_quic_t *      quic = conn->quic;

  if( quic->cb.tls_keylog )
    quic->cb.tls_keylog( quic->cb.quic_ctx, line );
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

  /* do we have bytes we can use? */
  if( FD_LIKELY( rcv_offset <= exp_offset && rcv_offset + rcv_sz > exp_offset ) ) {
    if( !conn->tls_hs ) {
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      conn->quic->metrics.conn_aborted_cnt++;
      conn->quic->metrics.conn_err_tls_fail_cnt++;
      return FD_QUIC_TLS_FAILED;
    }

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
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_CRYPTO_BUFFER_EXCEEDED );

      return FD_QUIC_PARSE_FAIL;
    }

    int process_rc = fd_quic_tls_process( conn->tls_hs );
    if( process_rc == FD_QUIC_TLS_FAILED ) {
      FD_DEBUG(
        fprintf( stderr, "fd_quic_tls_process error at: %s %s %d\n", __func__, __FILE__, __LINE__ )
      );
      /* if TLS fails, ABORT connection */

      /* if TLS returns an error, we present that as reason:
           FD_QUIC_CONN_REASON_CRYPTO_BASE + tls-alert
         otherwise, send INTERNAL_ERROR */
      uint alert = conn->tls_hs->alert;
      if( alert == 0u ) {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
      } else {
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_CRYPTO_BASE + alert );
      }

      /* don't process any more frames on this connection */
      return FD_QUIC_PARSE_FAIL;
    }

    /* successful, update rx_crypto_offset */
    conn->rx_crypto_offset[enc_level] += rcv_sz;
  } else {
    /* if data arrived early, we could buffer, but for now we simply won't ack */
    /* TODO buffer handshake data */
    if( rcv_offset > exp_offset ) return FD_QUIC_PARSE_FAIL;
  }

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  (void)context; (void)p; (void)p_sz;

  /* no "additional" bytes - all already accounted for */
  return 0;
}

void
fd_quic_service( fd_quic_t * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong now = fd_quic_now( quic );

  /* do we need to update the arp or routing tables? */
  fd_ip_t * ip = fd_quic_get_ip( quic );
  long ip_upd_period_ns = (long)5e9; /* every 5 seconds seems reasonable */
  if( FD_UNLIKELY( (long)( now - state->ip_table_upd ) > ip_upd_period_ns ) ) {
    fd_ip_arp_fetch( ip );
    fd_ip_route_fetch( ip );

    state->ip_table_upd = now;
  }

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
    conn->next_service_time = now + fd_quic_get_service_interval( quic );

    /* remove event, later reinserted at new time */
    service_queue_remove_min( state->service_queue );

    /* unset "in service queue" */
    conn->in_service = 0;

    if( conn->state == FD_QUIC_CONN_STATE_INVALID ) {
      /* connection shouldn't have been scheduled,
         and is now removed, so just continue */
      continue;
    }

    if( FD_UNLIKELY( now > conn->last_activity + conn->idle_timeout ) ) {
      /* rfc9000 10.1 Idle Timeout
         "... the connection is silently closed and its state is discarded
         when it remains idle for longer than the minimum of the
         max_idle_timeout value advertised by both endpoints." */
      FD_LOG_WARNING(( "connection closing due to timeout" ));
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
    } else {
      fd_quic_conn_service( quic, conn, now );
    }

    /* dead? don't reinsert, just clean up */
    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_DEAD:
        fd_quic_cb_conn_final( quic, conn ); /* inform user before freeing */
        fd_quic_conn_free( quic, conn );
        break;

      case FD_QUIC_CONN_STATE_INVALID:
        /* skip entirely */
        break;

      default:
        if( !conn->in_service ) {
          fd_quic_schedule_conn( conn );
        }
    }
  }
}

/* attempt to transmit buffered data

   prior to call, conn->tx_ptr points to the first free byte in tx_buf
   the data in tx_buf..tx_ptr is prepended by networking headers
   and put on the wire

   returns 0 if successful, or 1 otherwise */
uint
fd_quic_tx_buffered_raw(
    fd_quic_t *      quic,
    uchar **         tx_ptr_ptr,
    uchar *          tx_buf,
    ulong            tx_buf_sz,
    ulong *          tx_sz,
    uchar *          crypt_scratch,
    ulong            crypt_scratch_sz,
    uchar *          dst_mac_addr,
    ushort *         ipv4_id,
    uint             dst_ipv4_addr,
    ushort           src_udp_port,
    ushort           dst_udp_port,
    int              flush
) {

  /* TODO leave space at front of tx_buf for header
          then encode directly into it to avoid 1 copy */
  uchar *tx_ptr = *tx_ptr_ptr;
  long payload_sz = tx_ptr - tx_buf;

  /* nothing to do */
  if( FD_UNLIKELY( payload_sz<=0L ) ) {
    if( flush ) {
      /* send empty batch to flush tx */
      fd_aio_pkt_info_t aio_buf = { .buf = NULL, .buf_sz = 0 };
      int aio_rc = fd_aio_send( &quic->aio_tx, &aio_buf, 0, NULL, 1 );
      (void)aio_rc; /* don't care about result */
    }
    return 0u;
  }

  fd_quic_config_t * config = &quic->config;

  uchar * cur_ptr = crypt_scratch;
  ulong  cur_sz  = crypt_scratch_sz;

  /* TODO much of this may be prepared ahead of time */
  fd_quic_pkt_t pkt;

  memcpy( pkt.eth->dst, dst_mac_addr,                   6 );
  memcpy( pkt.eth->src, quic->config.link.src_mac_addr, 6 );
  pkt.eth->net_type = FD_ETH_HDR_TYPE_IP;

  pkt.ip4->verihl       = FD_IP4_VERIHL(4,5);
  pkt.ip4->tos          = (uchar)(config->net.dscp << 2); /* could make this per-connection or per-stream */
  pkt.ip4->net_tot_len  = (ushort)( 20 + 8 + payload_sz );
  pkt.ip4->net_id       = *ipv4_id++;
  pkt.ip4->net_frag_off = 0x4000u; /* don't fragment */
  pkt.ip4->ttl          = 64; /* TODO make configurable */
  pkt.ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  pkt.ip4->check        = 0;
  pkt.udp->net_sport    = src_udp_port;
  pkt.udp->net_dport    = dst_udp_port;
  pkt.udp->net_len      = (ushort)( 8 + payload_sz );
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
  ulong tag_sz = FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( (ulong)payload_sz + tag_sz > cur_sz ) ) {
    FD_LOG_WARNING(( "%s : payload too big for buffer", __func__ ));

    /* reset buffer, since we can't use its contents */
    *tx_ptr_ptr = tx_buf;
    *tx_sz  = tx_buf_sz;
    return FD_QUIC_FAILED;
  }
  fd_memcpy( cur_ptr, tx_buf, (ulong)payload_sz );

  cur_ptr += (ulong)payload_sz;
  cur_sz  -= (ulong)payload_sz;

  fd_aio_pkt_info_t aio_buf = { .buf = crypt_scratch, .buf_sz = (ushort)( cur_ptr - crypt_scratch ) };
  int aio_rc = fd_aio_send( &quic->aio_tx, &aio_buf, 1, NULL, flush );
  if( aio_rc == FD_AIO_ERR_AGAIN ) {
    /* transient condition - try later */
    return FD_QUIC_FAILED;
  } else if( aio_rc != FD_AIO_SUCCESS ) {
    FD_LOG_WARNING(( "Fatal error reported by aio peer" ));
    /* fallthrough to reset buffer */
  }

  /* after send, reset tx_ptr and tx_sz */
  *tx_ptr_ptr = tx_buf;
  *tx_sz  = tx_buf_sz;

  quic->metrics.net_tx_pkt_cnt += aio_rc==FD_AIO_SUCCESS;
  if (FD_LIKELY (aio_rc==FD_AIO_SUCCESS) ) {
    quic->metrics.net_tx_byte_cnt += aio_buf.buf_sz;
  }

  return FD_QUIC_SUCCESS; /* success */
}

uint fd_quic_tx_buffered( fd_quic_t *      quic,
                          fd_quic_conn_t * conn,
                          int              flush )
{
  fd_quic_endpoint_t *peer = &conn->peer[conn->cur_peer_idx];
  return fd_quic_tx_buffered_raw(
      quic,
      &conn->tx_ptr,
      conn->tx_buf,
      sizeof(conn->tx_buf),
      &conn->tx_sz,
      conn->crypt_scratch,
      sizeof(conn->crypt_scratch),
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
    fd_quic_retry_t     retry;
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
  fd_quic_conn_id_t *  conn_id      = &conn->our_conn_id[conn->cur_conn_id_idx];

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
      pkt_hdr->quic_pkt.initial.src_conn_id_len  = conn_id->sz;
      // .src_conn_id
      // .token
      pkt_hdr->quic_pkt.initial.len              = 0;  /* length of payload initially 0 */
      pkt_hdr->quic_pkt.initial.pkt_num          = pkt_number;

      fd_memcpy( pkt_hdr->quic_pkt.initial.dst_conn_id,
              peer_conn_id->conn_id,
              peer_conn_id->sz );
      fd_memcpy( pkt_hdr->quic_pkt.initial.src_conn_id,
              conn_id->conn_id,
              conn_id->sz );

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
      fd_memcpy( pkt_hdr->quic_pkt.handshake.src_conn_id,
              conn_id->conn_id,
              conn_id->sz );
      pkt_hdr->quic_pkt.handshake.src_conn_id_len = conn_id->sz;

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

/* transmit
     looks at each of the following dependent on state, and creates
     a packet to transmit:
       acks
       handshake data (tls)
       handshake done
       ping
       stream data */
void
fd_quic_conn_tx( fd_quic_t * quic, fd_quic_conn_t * conn ) {
  /* used for encoding frames into before encrypting */
  uchar *  crypt_scratch    = conn->crypt_scratch;
  ulong    crypt_scratch_sz = sizeof( conn->crypt_scratch );

  /* max packet size */
  /* TODO probably should be called tx_max_udp_payload_sz */
  ulong tx_max_datagram_sz = conn->tx_max_datagram_sz;

  fd_quic_pkt_hdr_t pkt_hdr;

  fd_quic_pkt_meta_t * pkt_meta         = NULL;
  ulong                pkt_meta_var_idx = 0UL;

  if( conn->tx_ptr != conn->tx_buf ) {
    fd_quic_tx_buffered( quic, conn, 0 );
    fd_quic_reschedule_conn( conn, 0 );
    return;
  }

  /* temporary usage
     data is populated, then encoded into a buffer
     so only one member in use */
  union {
    fd_quic_crypto_frame_t       crypto;
    fd_quic_ack_frame_t          ack;
    fd_quic_stream_frame_t       stream;
    fd_quic_max_stream_data_t    max_stream_data;
    fd_quic_max_data_frame_t     max_data;
    fd_quic_conn_close_0_frame_t conn_close_0;
    fd_quic_conn_close_1_frame_t conn_close_1;
    fd_quic_max_streams_frame_t  max_streams;
  } frame;

  /* choose enc_level to tx at */
  uint enc_level = fd_quic_tx_enc_level( conn );

  /* this test section is close to what we actually need
     just need to choose the packet number at which to start a
     key update, and store it on conn */

  // /* TESTING */
  // static ulong nxt_key_upd = 10000000;
  // if( enc_level == 3 && conn->pkt_number[2] >= nxt_key_upd ) {
  //   printf( "conn->pkt_number[2]=%lu  enc_level=%u\n", conn->pkt_number[2], enc_level );
  //   fflush( stdout );

  //   fd_quic_crypto_suite_t * suite = conn->suites[enc_level];
  //   conn->key_phase_upd = 1;

  //   if( fd_quic_gen_new_secrets( &conn->secrets, suite->hash ) != FD_QUIC_SUCCESS ) {
  //     printf( "fd_quic_gen_new_secrets failed\n" );
  //     conn->key_phase_upd = 0;
  //   }

  //   /* generate new keys */
  //   if( FD_UNLIKELY( fd_quic_gen_new_keys( &conn->new_keys[0],
  //                                          suite,
  //                                          suite->hash,
  //                                          conn->secrets.new_secret[0],
  //                                          conn->secrets.secret_sz[enc_level][0] )
  //         != FD_QUIC_SUCCESS ) ) {
  //     printf( "fd_quic_gen_new_secrets failed\n" );
  //     conn->key_phase_upd = 0;
  //   }
  //   if( FD_UNLIKELY( fd_quic_gen_new_keys( &conn->new_keys[1],
  //                                          suite,
  //                                          suite->hash,
  //                                          conn->secrets.new_secret[1],
  //                                          conn->secrets.secret_sz[enc_level][1] )
  //         != FD_QUIC_SUCCESS ) ) {
  //     printf( "fd_quic_gen_new_secrets failed\n" );
  //     conn->key_phase_upd = 0;
  //   }

  //   nxt_key_upd = conn->pkt_number[2] + 100000;
  // }

  /* nothing to send? */
  if( enc_level == ~0u ) {
    return;
  }

  uint closing    = 0; /* are we closing? */
  uint peer_close = 0; /* did peer request close? */

  /* check status */
  switch( conn->state ) {
    case FD_QUIC_CONN_STATE_DEAD:
      return;
    case FD_QUIC_CONN_STATE_PEER_CLOSE:
      peer_close = 1u;
      __attribute__((fallthrough));
    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
      closing = 1u;
  }

  int key_phase_upd = (int)conn->key_phase_upd;
  int key_phase     = (int)conn->key_phase;
  int key_phase_tx  = (int)key_phase ^ key_phase_upd;

  /* key phase flags to set on every relevant pkt_meta */
  uint key_phase_flags = fd_uint_if( enc_level == fd_quic_enc_level_appdata_id,
                                        ( fd_uint_if( key_phase_upd, FD_QUIC_PKT_META_FLAGS_KEY_UPDATE, 0 ) |
                                          fd_uint_if( key_phase_tx,  FD_QUIC_PKT_META_FLAGS_KEY_PHASE,  0 ) ),
                                        0 );

  /* get time, and set reschedule time for at most the idle timeout */
  ulong now    = fd_quic_now( quic );
  ulong expiry = now + conn->idle_timeout;

  while( enc_level != ~0u ) {
    ulong              frame_sz     = 0;
    ulong              tot_frame_sz = 0;
    ulong              data_sz      = 0;
    uchar const *      data         = NULL;
    fd_quic_stream_t * stream       = NULL;
    uint               initial_pkt  = 0;    /* is this the first initial packet? */
    int                last_byte    = 0;

    /* do we have space for pkt_meta? */
    pkt_meta = fd_quic_pkt_meta_allocate( &conn->pkt_meta_pool );
    if( FD_UNLIKELY( !pkt_meta ) ) {
      FD_DEBUG(
          printf( "%s - packet metadata free list is empty\n", __func__ );
          )
      /* cannot abort here, because there are no pkt_meta
         to use for sending packets */

      /* retry pkt_meta
         This should only occur when packet loss has occurred,
         or the amount packet metadata is too small */
      fd_quic_pkt_meta_retry( quic, conn, 1 /* force */ );

      pkt_meta = fd_quic_pkt_meta_allocate( &conn->pkt_meta_pool );
      if( FD_UNLIKELY( !pkt_meta ) ) {
        /* failure here is a logic error
           this connection is no longer usable
           so set to DEAD to be freed cleanly */
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        quic->metrics.conn_aborted_cnt++;
      }

      break;
    }

    /* initialize expiry */
    pkt_meta->expiry = expiry;

    /* remaining in datagram */
    /* invariant: tx_buf >= tx_ptr */
    ulong datagram_rem = tx_max_datagram_sz - (ulong)( conn->tx_ptr - conn->tx_buf );

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

    pkt_meta->pkt_number = pkt_number;

    /* this is the start of a new quic packet
       cur_ptr points at the next byte to fill with a quic pkt */
    /* currently, cur_ptr just points at the start of crypt_scratch
       each quic packet gets encrypted into tx_buf, and the space in
       crypt_scratch is reused */

    /* are we the client initial packet? */
    ulong hs_data_offset = conn->hs_sent_bytes[enc_level];
    initial_pkt = (uint)( hs_data_offset == 0 ) & (uint)( !conn->server ) & (uint)( enc_level == fd_quic_enc_level_initial_id );

    /* populate the quic packet header */
    fd_quic_pkt_hdr_populate( &pkt_hdr, enc_level, pkt_number, conn, (uchar)key_phase_tx, initial_pkt );

    ulong initial_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, enc_level );

    /* if we don't have space for an initial header plus
       16 for sample, 16 for tag and 3 bytes for expansion,
       try tx to free space */
    ulong min_rqd = FD_QUIC_CRYPTO_TAG_SZ + FD_QUIC_CRYPTO_SAMPLE_SZ + 3;
    if( initial_hdr_sz + min_rqd > cur_sz ) {
      /* deallocate packet metadata */
      fd_quic_pkt_meta_deallocate( &conn->pkt_meta_pool, pkt_meta );

      /* try to free space */
      fd_quic_tx_buffered( quic, conn, 0 );

      /* we have lots of space, so try again */
      if( conn->tx_buf == conn->tx_ptr ) {
        enc_level = fd_quic_tx_enc_level( conn );
        continue;
      }

      /* reschedule, since some data was unable to be sent */
      /* TODO might want to add a backoff here */
      fd_quic_reschedule_conn( conn, 0 );

      break;
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

    /* put range of offsets into packet meta, so the data may be freed easily on
       ack */

    /* do we have unsent acks? */
    fd_quic_ack_t * ack_head = NULL;

    /* if we're sending at a particular enc level always include the unsent acks we can
       regardless of the ack_time */
    fd_quic_ack_t * tmp_ack = conn->acks_tx[enc_level];
    while( tmp_ack ) {
      if( tmp_ack->flags & FD_QUIC_ACK_FLAGS_SENT ) {
        tmp_ack = tmp_ack->next;
      } else {
        break;
      }
    }
    if( tmp_ack && !( tmp_ack->flags & FD_QUIC_ACK_FLAGS_SENT ) ) {
      ack_head = tmp_ack;
    }

    /* if we have acks, add them */
    if( ack_head ) {
#if 0
      /* TODO - more ranges */
      /* determine number of ack ranges, and size? */
      ulong ack_range_sz  = 0;
      ulong ack_range_cnt = 0;

      fd_quic_ack_range_frag_t ack_range_frag[1];

      /* TODO ensure acks are in order in linked list */
      ulong cur_pkt_num_lo = ack_head->pkt_number.offset_lo;
      ulong cur_pkt_num_hi = ack_head->pkt_number.offset_hi;

      /* start with next */
      fd_quic_ack_t * tmp_ack_ptr = ack_head->next;
      while( tmp_ack_ptr ) {
        ulong tmp_pkt_num_lo = tmp_ack_ptr->pkt_number.offset_lo;
        ulong tmp_pkt_num_hi = tmp_ack_ptr->pkt_number.offset_hi;

        /*
        if( */

        tmp_ack_ptr = tmp_ack_ptr->next;
      }
#endif
      while( ack_head ) {
        if( !(ack_head->flags & FD_QUIC_ACK_FLAGS_SENT ) ) {

          /* put ack frame */
          frame.ack.type            = 0x02u; /* type 0x02 is the base ack, 0x03 indicates ECN */
          frame.ack.largest_ack     = ack_head->pkt_number.offset_hi - 1u;
          frame.ack.ack_delay       = fd_quic_now( quic ) - ack_head->pkt_rcvd;
          frame.ack.ack_range_count = 0; /* no fragments */
          frame.ack.first_ack_range = ack_head->pkt_number.offset_hi - ack_head->pkt_number.offset_lo - 1u;

          /* calc size of ack frame */
          frame_sz  = fd_quic_encode_footprint_ack_frame( &frame.ack );

          if( payload_ptr + frame_sz < payload_end ) {
            frame_sz = fd_quic_encode_ack_frame( payload_ptr,
                (ulong)( payload_end - payload_ptr ),
                &frame.ack );
            if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
              /* shouldn't happen */
              FD_LOG_WARNING(( "failed to encode ack" ));
            } else {
              payload_ptr  += frame_sz;
              tot_frame_sz += frame_sz;

              /* must add acks to packet metadata */
              ack_head->tx_pkt_number = pkt_number;
              pkt_meta->flags         |= FD_QUIC_PKT_META_FLAGS_ACK;

              /* ack frames don't really expire, but we still want to reclaim the pkt_meta */
              pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + (ulong)1e9 );
            }
          }
        }

        ack_head = ack_head->next;
      }
    }

    /* closing? */
    if( FD_UNLIKELY( closing ) ) {
      if( !( conn->flags & FD_QUIC_CONN_FLAGS_CLOSE_SENT ) ) {
        /* only send one unless timeout before ack */
        conn->flags |= FD_QUIC_CONN_FLAGS_CLOSE_SENT;

        if( conn->reason != 0u || peer_close ) {
          frame.conn_close_0.error_code           = conn->reason;
          frame.conn_close_0.frame_type           = 0u; /* we do not know the frame in question */
          frame.conn_close_0.reason_phrase_length = 0u; /* no reason phrase */

          /* output */
          frame_sz = fd_quic_encode_conn_close_0_frame( payload_ptr,
                                                        (ulong)( payload_end - payload_ptr ),
                                                        &frame.conn_close_0 );
        } else {
          frame.conn_close_1.error_code           = conn->app_reason;
          frame.conn_close_1.reason_phrase_length = 0u; /* no reason phrase */

          /* output */
          frame_sz = fd_quic_encode_conn_close_1_frame( payload_ptr,
                                                        (ulong)( payload_end - payload_ptr ),
                                                        &frame.conn_close_1 );
        }

        if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
          FD_LOG_WARNING(( "%s - fd_quic_encode_crypto_frame failed, but space "
                "should have been available", __func__ ));
          break;
        }

        /* move ptr up */
        payload_ptr  += frame_sz;
        tot_frame_sz += frame_sz;

        /* update packet meta */
        pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_CLOSE;
        pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );
      }
    } else {
      /* if handshake data, add it */
      fd_quic_tls_hs_data_t * hs_data   = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
      ulong                   hs_offset = 0; /* offset within the current hs_data */

      /* either include handshake data or stream data, but not both */
      ulong sent_offset = conn->hs_sent_bytes[enc_level];
      ulong ackd_offset = conn->hs_ackd_bytes[enc_level];
      if( hs_data ) {
        /* offset within stream */
        ulong offset = fd_ulong_max( sent_offset, ackd_offset );

        /* track pkt_meta values */
        ulong offset_lo = offset;
        ulong offset_hi = offset;

        data_sz = 0;
        (void)data;

        while( hs_data ) {
          /* skip data we've sent */
          if( hs_data->offset + hs_data->data_sz > offset ) {
            if( FD_UNLIKELY( hs_data->offset > offset ) ) {
              /* we have a gap - this shouldn't happen */
              FD_LOG_WARNING(( "%s - gap in TLS handshake data", __func__ ));
              /* TODO should probably tear down connection */
              break;
            }

            /* encode hs_data into frame */
            hs_offset = offset - hs_data->offset;

            /* handshake data to send */
            uchar const * cur_data    = hs_data->data    + hs_offset;
            ulong         cur_data_sz = hs_data->data_sz - hs_offset;

            /* build crypto frame */
            frame.crypto.offset      = offset;
            frame.crypto.length      = cur_data_sz;
            frame.crypto.crypto_data = cur_data;

            /* calc size of crypto frame, including */
            frame_sz = fd_quic_encode_footprint_crypto_frame( &frame.crypto );

            /* not enough space? */
            ulong over = 0;
            if( payload_ptr + frame_sz > payload_end ) {
              over = frame_sz - (ulong)( payload_end - payload_ptr );
            }

            if( FD_UNLIKELY( over >= cur_data_sz ) ) {
              break;
            }

            cur_data_sz -= over;
            frame.crypto.length = cur_data_sz;

            /* output */
            frame_sz = fd_quic_encode_crypto_frame( payload_ptr,
                                                    (ulong)( payload_end - payload_ptr ),
                                                    &frame.crypto );

            if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
              FD_LOG_WARNING(( "%s - fd_quic_encode_crypto_frame failed, but space "
                    "should have been available", __func__ ));
              break;
            }

            /* move ptr up */
            payload_ptr  += frame_sz;
            tot_frame_sz += frame_sz;

            /* update pkt_meta values */
            offset_hi += cur_data_sz;

            /* move to next hs_data */
            offset      += cur_data_sz;
            data_sz     += cur_data_sz;

            /* TODO load more hs_data into a crypto frame, if available
               currently tricky, because encode_crypto_frame copies payload */

          } else {
            hs_data = fd_quic_tls_get_next_hs_data( conn->tls_hs, hs_data );
          }
        }

        /* update packet meta */
        if( offset_hi > offset_lo ) {
          pkt_meta->flags          |= FD_QUIC_PKT_META_FLAGS_HS_DATA;
          pkt_meta->range.offset_lo = offset_lo;
          pkt_meta->range.offset_hi = offset_hi;
          pkt_meta->expiry          = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );
        }

      }

      /* are we at application level of encryption? */
      if( enc_level == fd_quic_enc_level_appdata_id ) {
        if( conn->handshake_done_send /* && !conn->handshake_done_ackd TODO */ ) {
          /* send handshake done frame */
          frame_sz = 1;
          pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_HS_DONE;
          pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );
          *(payload_ptr++) = 0x1eu;
          tot_frame_sz++;
        }

        if( conn->upd_pkt_number >= pkt_number ) {
          if( ( conn->flags & FD_QUIC_CONN_FLAGS_MAX_DATA ) &&
              ( conn->rx_max_data > conn->rx_max_data_ackd ) ) {
            /* send max_data frame */
            frame.max_data.max_data = conn->rx_max_data;

            /* attempt to write into buffer */
            frame_sz = fd_quic_encode_max_data_frame( payload_ptr,
                                                      (ulong)( payload_end - payload_ptr ),
                                                      &frame.max_data );
            if( FD_LIKELY( frame_sz != FD_QUIC_PARSE_FAIL ) ) {
              /* successful? then update payload_ptr and tot_frame_sz */
              payload_ptr  += frame_sz;
              tot_frame_sz += frame_sz;

              /* set flag on pkt meta */
              pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_MAX_DATA;
              pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

              if( pkt_meta_var_idx < FD_QUIC_PKT_META_VAR_MAX ) {
                pkt_meta->var[pkt_meta_var_idx].key =
                    (fd_quic_pkt_meta_key_t){
                      .type      = FD_QUIC_PKT_META_TYPE_OTHER,
                      .flags     = FD_QUIC_CONN_FLAGS_MAX_DATA
                    };
                pkt_meta_var_idx++;
                pkt_meta->var_sz = (uchar)pkt_meta_var_idx; /* TODO consolidate var_sz updates */
              }

              conn->upd_pkt_number = pkt_number;
            }
          }

          /* 0x00 Client-Initiated, Bidirectional
             0x01 Server-Initiated, Bidirectional
             0x02 Client-Initiated, Unidirectional
             0x03 Server-Initiated, Unidirectional
             */
          if( conn->flags & FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR ) {
            /* send max streams frame */
            ulong stream_type_idx = 2u | !conn->server;
            frame.max_streams.stream_type = 1;
            frame.max_streams.max_streams = conn->max_streams[stream_type_idx];

            /* attempt to write into buffer */
            frame_sz = fd_quic_encode_max_streams_frame( payload_ptr,
                                                         (ulong)( payload_end - payload_ptr ),
                                                         &frame.max_streams );
            if( FD_LIKELY( frame_sz != FD_QUIC_PARSE_FAIL ) ) {
              /* successful? then update payload_ptr and tot_frame_sz */
              payload_ptr  += frame_sz;
              tot_frame_sz += frame_sz;

              /* set flag on pkt meta */
              pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR;
              pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

              conn->upd_pkt_number = pkt_number;
            }
          }

          if( conn->flags & FD_QUIC_CONN_FLAGS_MAX_STREAMS_BIDIR ) {
            /* send max streams frame */
            ulong stream_type_idx = 0u | !conn->server;
            frame.max_streams.stream_type = 0;
            frame.max_streams.max_streams = conn->max_streams[stream_type_idx];

            /* attempt to write into buffer */
            frame_sz = fd_quic_encode_max_streams_frame( payload_ptr,
                                                         (ulong)( payload_end - payload_ptr ),
                                                         &frame.max_streams );
            if( FD_LIKELY( frame_sz != FD_QUIC_PARSE_FAIL ) ) {
              /* successful? then update payload_ptr and tot_frame_sz */
              payload_ptr  += frame_sz;
              tot_frame_sz += frame_sz;

              /* set flag on pkt meta */
              pkt_meta->flags |= FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_BIDIR;
              pkt_meta->expiry = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

              conn->upd_pkt_number = pkt_number;
            }
          }
        }

        if( !hs_data && conn->handshake_complete ) {
#if 0
          fd_quic_stream_t ** streams         = conn->streams;
          ulong               tot_num_streams = conn->tot_num_streams;
          for( ulong j = 0; j < tot_num_streams; ++j ) {
            fd_quic_stream_t * cur_stream = streams[j];

            /* any unsent data? */
            if( cur_stream->tx_buf.head > cur_stream->tx_sent ) {
              stream = cur_stream;
            }

            if( cur_stream->stream_flags & FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA &&
                cur_stream->upd_pkt_number >= pkt_number ) {
              /* send max_stream_data frame */
              frame.max_stream_data.stream_id       = cur_stream->stream_id;
              frame.max_stream_data.max_stream_data = cur_stream->rx_max_stream_data;

              /* attempt to write into buffer */
              frame_sz = fd_quic_encode_max_stream_data( payload_ptr,
                                                         (ulong)( payload_end - payload_ptr ),
                                                         &frame.max_stream_data );
              if( FD_LIKELY( frame_sz != FD_QUIC_PARSE_FAIL ) ) {
                /* successful? then update payload_ptr and tot_frame_sz */
                payload_ptr  += frame_sz;
                tot_frame_sz += frame_sz;

                /* and set actual pkt_number on the stream */
                cur_stream->upd_pkt_number = pkt_number;

                /* set flag on pkt meta */
                pkt_meta->flags          |= FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA;
              } else {
                /* failed to encode - push to next packet */
                cur_stream->upd_pkt_number++;
              }
            }
          }
#else
          /* loop serves two purposes:
               1. finds a stream with data to send
               2. appends max_stream_data frames as necessary */
          fd_quic_stream_t * sentinel   = conn->send_streams;
          fd_quic_stream_t * cur_stream = sentinel->next;
          while( !cur_stream->sentinel ) {
            fd_quic_stream_t * nxt_stream = cur_stream->next;

            if( cur_stream->upd_pkt_number >= pkt_number ) {
              uint stream_flags_mask = FD_QUIC_STREAM_FLAGS_UNSENT
                                     | FD_QUIC_STREAM_FLAGS_TX_FIN;
              if( !stream && ( cur_stream->stream_flags & stream_flags_mask ) ) {
                stream = cur_stream;
              }

              if( cur_stream->stream_flags & FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA ) {
                /* send max_stream_data frame */
                frame.max_stream_data.stream_id       = cur_stream->stream_id;
                frame.max_stream_data.max_stream_data = cur_stream->rx_max_stream_data;

                /* attempt to write into buffer */
                frame_sz = fd_quic_encode_max_stream_data( payload_ptr,
                                                           (ulong)( payload_end - payload_ptr ),
                                                           &frame.max_stream_data );
                if( FD_LIKELY( frame_sz != FD_QUIC_PARSE_FAIL ) ) {
                  /* successful? then update payload_ptr and tot_frame_sz */
                  payload_ptr  += frame_sz;
                  tot_frame_sz += frame_sz;

                  /* and set actual pkt_number on the stream */
                  cur_stream->upd_pkt_number = pkt_number;

                  /* set flag on pkt meta */
                  pkt_meta->flags           |= FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA;
                  pkt_meta->expiry           = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

                  /* remove flag from cur_stream */
                  cur_stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
                  if( !FD_QUIC_STREAM_ACTION( cur_stream ) ) {
                    /* remove cur_stream from action list */
                    FD_QUIC_STREAM_LIST_REMOVE( cur_stream );
                  }
                }
              }
            }

            cur_stream = nxt_stream;
          }
#endif

          if( stream ) {

            /* how many bytes are we allowed to send on the stream and on the connection? */
            ulong allowed_stream = stream->tx_max_stream_data - stream->tx_tot_data;
            ulong allowed_conn   = conn->tx_max_data - conn->tx_tot_data;
            ulong allowed        = allowed_conn < allowed_stream ? allowed_conn : allowed_stream;

            /* how much data to send */
            data_sz = stream->tx_buf.head - stream->tx_sent;

            int fin_state = !!(stream->state & FD_QUIC_STREAM_STATE_TX_FIN);

            /* initialize last_byte to fin_state */
            last_byte = fin_state;

            /* offset of the first byte we're sending */
            ulong stream_off = stream->tx_sent;

            /* abide by peer flow control */
            if( data_sz > allowed ) {
              data_sz = allowed;
              last_byte = 0;
            }

            /* do we still have data we can send? */
            if( data_sz > 0u || last_byte ) {
              /* populate frame.stream */
              frame.stream.stream_id = stream->stream_id;

              /* optional fields */
              frame.stream.offset_opt = ( stream_off != 0 );
              frame.stream.offset     = stream_off;

              frame.stream.length_opt = 1; /* always include length */
              frame.stream.length     = data_sz;

              frame.stream.fin_opt    = (uchar)last_byte;

              /* calc size of stream frame */
              frame_sz = data_sz + fd_quic_encode_footprint_stream_frame( &frame.stream );

              /* over? */
              ulong over = 0;
              if( (long)frame_sz > payload_end - payload_ptr ) {
                over = frame_sz - (ulong)( payload_end - payload_ptr );

                /* since we are not sending the last byte of the stream
                   reset these values */
                frame.stream.fin_opt = (uchar)0;
                last_byte            = 0;
              }

              if( over >= data_sz ) {
                /* can't send in this packet */
                break;
              }

              /* adjust to fit */
              data_sz            -= over;
              frame.stream.length = data_sz;

              /* do we still have data we can send? */
              if( data_sz > 0u || last_byte ) {

                /* output */
                frame_sz = fd_quic_encode_stream_frame( payload_ptr,
                    (ulong)( payload_end - payload_ptr ),
                    &frame.stream );

                if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
                  FD_LOG_WARNING(( "%s - fd_quic_encode_stream_frame failed, but space "
                        "should have been available", __func__ ));
                  break;
                }

                /* move ptr up */
                payload_ptr  += frame_sz;
                tot_frame_sz += frame_sz;

                /* copy buffered data (tx_buf) into tx data (payload_ptr) */
                fd_quic_buffer_t * tx_buf = &stream->tx_buf;

                /* load data from tx_buf into payload_ptr
                   data_sz was already adjusted to fit
                   this loads but does not adjust tail pointer (consume) */
                fd_quic_buffer_load( tx_buf, stream_off, payload_ptr, data_sz );

                /* adjust ptr and size */
                payload_ptr  += data_sz;
                tot_frame_sz += data_sz;

                /* packet metadata */
                pkt_meta->flags          |= FD_QUIC_PKT_META_FLAGS_STREAM;
                pkt_meta->stream_id       = stream->stream_id;
                pkt_meta->range.offset_lo = stream_off;
                pkt_meta->range.offset_hi = stream_off + data_sz;
                pkt_meta->expiry          = fd_ulong_min( pkt_meta->expiry, now + 3u * conn->rtt );

                stream->upd_pkt_number = pkt_number;
              }
            }
          }
        }
      }
    }

    /* did we add any frames? */

    if( !pkt_meta->flags ) {
      /* free pkt_meta */
      fd_quic_pkt_meta_deallocate( &conn->pkt_meta_pool, pkt_meta );

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
      fd_quic_tx_buffered( quic, conn, 0 );

      /* we have lots of space, so try again */
      if( conn->tx_buf == conn->tx_ptr ) {
        enc_level = fd_quic_tx_enc_level( conn );
        continue;
      }
    }

    /* first initial frame is padded to FD_QUIC_MIN_INITIAL_PKT_SZ
       all short quic packets are padded so 16 bytes of sample are available */
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
      FD_LOG_WARNING(( "%s - fd_quic_pkt_hdr_encode failed, even though there should "
            "have been enough space", __func__ ));

      /* reschedule, since some data was unable to be sent */
      fd_quic_reschedule_conn( conn, 0 );

      /* free the pkt_meta */
      fd_quic_pkt_meta_deallocate( &conn->pkt_meta_pool, pkt_meta );

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
    fd_memcpy( conn->tx_ptr, cur_ptr, quic_pkt_sz );
    fd_memset( conn->tx_ptr + quic_pkt_sz, 0, 16 );

    /* update tx_ptr and tx_sz */
    conn->tx_ptr += quic_pkt_sz + 16;
    conn->tx_sz  -= quic_pkt_sz + 16;

    (void)act_hdr_sz;
#else
    ulong   quic_pkt_sz    = (ulong)( payload_ptr - cur_ptr );
    ulong   cipher_text_sz = conn->tx_sz;
    uchar * hdr            = cur_ptr;
    ulong   hdr_sz         = act_hdr_sz;
    uchar * pay            = hdr + hdr_sz;
    ulong   pay_sz         = quic_pkt_sz - hdr_sz;

    fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

    int server = conn->server;

    fd_quic_crypto_keys_t * hp_keys  = &conn->keys[enc_level][server];
    fd_quic_crypto_keys_t * pkt_keys = key_phase_upd ? &conn->new_keys[server]
                                                     : &conn->keys[enc_level][server];

    pkt_meta->flags |= key_phase_flags;

    if( FD_UNLIKELY( fd_quic_crypto_encrypt( conn->tx_ptr, &cipher_text_sz, hdr, hdr_sz,
          pay, pay_sz, suite, pkt_keys, hp_keys ) != FD_QUIC_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_quic_crypto_encrypt failed" ));

      /* reschedule, since some data was unable to be sent */
      fd_quic_reschedule_conn( conn, 0 );

      /* free the pkt_meta */
      fd_quic_pkt_meta_deallocate( &conn->pkt_meta_pool, pkt_meta );

      /* this situation is unlikely to improve, so kill the connection */
      conn->state = FD_QUIC_CONN_STATE_DEAD;
      quic->metrics.conn_aborted_cnt++;
      quic->metrics.conn_err_tls_fail_cnt++;
      break;
    }

    /* update tx_ptr and tx_sz */
    conn->tx_ptr += cipher_text_sz;
    conn->tx_sz  -= cipher_text_sz;
#endif

    /* update packet metadata with summary info */
    pkt_meta->pkt_number = pkt_number;
    pkt_meta->pn_space   = (uchar)pn_space;
    pkt_meta->enc_level  = (uchar)enc_level;

    /* update ack metadata */
    fd_quic_ack_t * cur_ack = conn->acks_tx[enc_level];
    while( cur_ack ) {
      if( cur_ack->tx_pkt_number == pkt_number ) {
        cur_ack->flags |= FD_QUIC_ACK_FLAGS_SENT;
      }

      cur_ack = cur_ack->next;
    }

    /* did we send handshake data? */
    if( pkt_meta->flags & FD_QUIC_PKT_META_FLAGS_HS_DATA ) {
      conn->hs_sent_bytes[enc_level] += data_sz;
    }

    /* did we send stream data? */
    if( pkt_meta->flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
      /* move sent pointer up */
      stream->tx_sent += data_sz;

      /* update flow control */
      stream->tx_tot_data += data_sz;
      conn->tx_tot_data   += data_sz;

      /* sent everything, may need to remove from action list */
      if( stream->tx_buf.head == stream->tx_sent
          && stream->stream_flags ) {
        /* remove from sent */
        stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_UNSENT;
        if( last_byte ) {
          stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_TX_FIN;
        }
        if( !FD_QUIC_STREAM_ACTION( stream ) ) {
          /* remove from list */
          FD_QUIC_STREAM_LIST_REMOVE( stream );
        }
      } else {
        /* didn't send everything, so reset upd_pkt_number */
        stream->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
      }
    }

    /* did we send handshake-done? */
    if( pkt_meta->flags & FD_QUIC_PKT_META_FLAGS_HS_DONE ) {
      conn->handshake_done_send = 0;
    }

    /* track min expiry for rescheduling later */
    expiry = fd_ulong_min( expiry, pkt_meta->expiry );

    /* add to sent list */
    fd_quic_pkt_meta_push_back( &conn->pkt_meta_pool.sent[enc_level], pkt_meta );

    /* clear pkt_meta for next loop */
    pkt_meta = NULL;

    if( enc_level == fd_quic_enc_level_appdata_id ) {
      /* short header must be last in datagram
         so send in packet immediately */
      fd_quic_tx_buffered( quic, conn, 0 );

      if( conn->tx_ptr == conn->tx_buf ) {
        enc_level = fd_quic_tx_enc_level( conn );
        continue;
      }

      /* drop packet */
      /* this is a workaround for leaving a short=header-packet in the buffer
         for the next tx_conn call. Next time around the tx_conn call will
         not be aware that the buffer cannot be added to */
      conn->tx_ptr = conn->tx_buf;
      conn->tx_sz  = sizeof( conn->tx_buf );

      break;
    }

    /* choose enc_level to tx at */
    enc_level = fd_quic_tx_enc_level( conn );
  }

  /* try to send? */
  fd_quic_tx_buffered( quic, conn, 1 );

  /* reschedule based on expiry */
  fd_quic_reschedule_conn( conn, expiry );
}

void
fd_quic_send_arp( fd_quic_t *      quic,
                  fd_quic_conn_t * conn,
                  uint             next_hop_ip_addr,
                  uint             ifindex ) {
  fd_ip_t * ip   = fd_quic_get_ip( quic );
  ulong     wait = (ulong)1e6; /* default wait for next arp action is 1ms */

  ulong now = fd_quic_now( quic );

  /* prepare kernel ARP table, else ARP reply will be ignored by the kernel */
  int arp_table_rtn = fd_ip_update_arp_table( ip, next_hop_ip_addr, ifindex );
  switch( arp_table_rtn ) {
    case FD_IP_RETRY:   wait = (ulong)50e3; __attribute__((fallthrough));
    case FD_IP_SUCCESS: (void)0;            __attribute__((fallthrough));
    case FD_IP_PROBE_RQD:
      fd_quic_reschedule_conn( conn, now + wait );
      break;

    case FD_IP_ERROR:
      fd_quic_reschedule_conn( conn, now + (ulong)100e6 );
      return;

    default:
      FD_LOG_WARNING(( "Unhandled return value from fd_ip_update_arp_table: %d",
            arp_table_rtn ));
      fd_quic_reschedule_conn( conn, now + (ulong)100e6 );
      /* try sending anyway */
  }

  /* need ip_addr in host order */
  uint host_ip_addr = fd_uint_bswap( quic->config.net.ip_addr );

  /* load an ARP packet */
  uchar buf[1024];
  ulong arp_len = 0;
  if( fd_ip_arp_gen_arp_probe( buf,
                               sizeof( buf ),
                               &arp_len,
                               next_hop_ip_addr,
                               host_ip_addr,
                               quic->config.link.src_mac_addr ) ) {
    FD_LOG_WARNING(( "fd_ip_arp_gen_arp_probe failed" ));
    return;
  }

  /* send it */
  fd_aio_pkt_info_t aio_buf = { .buf = buf, .buf_sz = (ushort)arp_len };
  int aio_rc = fd_aio_send( &quic->aio_tx, &aio_buf, 1, NULL, 1 /* flush */ );
  if( aio_rc == FD_AIO_ERR_AGAIN ) {
    /* transient condition */
    return;
  } else if( aio_rc != FD_AIO_SUCCESS ) {
    FD_LOG_WARNING(( "Fatal error reported by aio peer" ));
    /* fallthrough to reset buffer */
  }
}

void
fd_quic_conn_service( fd_quic_t * quic, fd_quic_conn_t * conn, ulong now ) {
  (void)now;
  /* are we handling ARP? */
  int   arp_status        = conn->arp_status;
  ulong arp_update_period = (ulong)( 500e6 );
  if( FD_UNLIKELY( arp_status == FD_ARP_STATUS_WAITING  ||
                   arp_status == FD_ARP_STATUS_REQUIRED ||
                   now        >  conn->arp_update + arp_update_period ) ) {
    /* get ip */
    fd_ip_t * ip = fd_quic_get_ip( quic );

    /* get current peer info */
    fd_quic_endpoint_t *peer = &conn->peer[conn->cur_peer_idx];

    /* ensure we have an updated arp table */
    if( arp_status == FD_ARP_STATUS_WAITING ) {
      fd_ip_arp_fetch( ip );
    }

    /* do routing */
    uint   dst_ip_addr      = peer->net.ip_addr;
    uchar  arp_mac_addr[6]  = {0};
    uint   arp_next_ip_addr = 0;
    uint   arp_ifindex      = 0;
    uint   arp_host_dst_ip  = fd_uint_bswap( dst_ip_addr );
    int arp_rtn = fd_ip_route_ip_addr( arp_mac_addr,
                                       &arp_next_ip_addr,
                                       &arp_ifindex,
                                       ip,
                                       arp_host_dst_ip );
    if( FD_LIKELY( arp_rtn == FD_IP_SUCCESS ) ) {
      memcpy( peer->mac_addr, arp_mac_addr, 6 );
      conn->arp_status = FD_ARP_STATUS_RESOLVED;
      conn->arp_update = now;
    } else {
      switch( arp_rtn ) {
        case FD_IP_PROBE_RQD:
          conn->arp_status = FD_ARP_STATUS_WAITING;

          /* send ARP */
          fd_quic_send_arp( quic, conn, arp_next_ip_addr, arp_ifindex );

          /* may have no MAC address, but may resolve later udpsock, for example,
          so continue */
          break;

        case FD_IP_NO_ROUTE:
          FD_LOG_WARNING(( "No route to host 0x%08x", dst_ip_addr ));

          /* wait for a period and retry */
          fd_quic_reschedule_conn( conn, now + (ulong)1e9 );
          return;
        default:
          FD_LOG_WARNING(( "Unexpected routing for host 0x%08x. Code: %x",
                           dst_ip_addr,
                           arp_rtn ));

          /* wait for a period and retry */
          fd_quic_reschedule_conn( conn, now + (ulong)1e9 );
          return;
      }
    }
  }


  /* handle expiry on pkt_meta */
  fd_quic_pkt_meta_retry( quic, conn, 0 /* don't force */ );

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

            /* user callback */
            fd_quic_cb_conn_new( quic, conn );
          }
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

        /* this will make the service call free the connection */
        conn->state = FD_QUIC_CONN_STATE_DEAD; /* TODO need draining state wait for 3 * TPO */
        quic->metrics.conn_closed_cnt++;

        break;

    case FD_QUIC_CONN_STATE_ABORT:
        /* transmit the failure reason */
        fd_quic_conn_tx( quic, conn );

        /* this will make the service call free the connection */
        conn->state = FD_QUIC_CONN_STATE_DEAD;
        quic->metrics.conn_aborted_cnt++;

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
    FD_LOG_WARNING(( "double free detected" ));
    return;
  }

  conn->state = FD_QUIC_CONN_STATE_INVALID;

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* remove connection ids from conn_map */

  /* loop over connection ids, and remove each */
  for( ulong j=0; j<conn->our_conn_id_cnt; ++j ) {
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( state->conn_map, &conn->our_conn_id[j] );
    if( entry ) {
      entry->conn = NULL;

      fd_quic_conn_map_remove( state->conn_map, entry );
    }
  }

  /* remove from orig_dst_conn_id */
  {
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( state->conn_map, &conn->orig_dst_conn_id );
    if( entry ) {
      entry->conn = NULL;

      fd_quic_conn_map_remove( state->conn_map, entry );
    }
  }

  /* find conn in events, then remove */
  /* FIXME O(n) scales badly with number of conns (#266) */
  ulong             event_idx = 0;
  ulong             cnt   = service_queue_cnt( state->service_queue );
  for( ulong j = 0; j < cnt; ++j ) {
    fd_quic_event_t * cur_event = state->service_queue + j;
    if( cur_event->conn == conn ) {
      /* remove */
      service_queue_remove( state->service_queue, event_idx );
    }
  }

  /* remove all stream ids from map, and free stream */
  ulong tot_num_streams = conn->tot_num_streams;
  for( ulong j = 0; j < tot_num_streams; ++j ) {
    fd_quic_stream_t * stream = conn->streams[j];
    if( stream->stream_id != FD_QUIC_STREAM_ID_UNUSED ) {
      fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream->stream_id, NULL );
      if( stream_entry ) {
        /* fd_quic_stream_free calls fd_quic_stream_map_remove */
        /* TODO we seem to be freeing more streams than expected here */
        if( stream_entry->stream &&
            ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) == 0 ) {
          fd_quic_cb_stream_notify( quic, stream, stream->context, FD_QUIC_NOTIFY_ABORT );
        }

        conn->num_streams[stream->stream_id&3]--;

        fd_quic_stream_map_remove( conn->stream_map, stream_entry );
        stream->stream_id = FD_QUIC_STREAM_ID_UNUSED;
        stream->stream_flags = 0;
        FD_QUIC_STREAM_LIST_REMOVE( stream );
        FD_QUIC_STREAM_LIST_INSERT_AFTER( conn->unused_streams, stream );
      } else {
        FD_LOG_WARNING(( "stream %lu not in stream_map", (ulong)stream->stream_id ));
      }
    }
  }

  /* if any stream map entries are left over, remove them
     this should not occur, so this branch should not execute
     but if a stream doesn't get cleaned up properly, this fixes
     the stream map */
  if( fd_quic_stream_map_key_cnt( conn->stream_map ) > 0 ) {
    FD_LOG_WARNING(( "stream_map not empty. cnt: %lu",
          (ulong)fd_quic_stream_map_key_cnt( conn->stream_map ) ));
    while( fd_quic_stream_map_key_cnt( conn->stream_map ) > 0 ) {
      int removed = 0;
      for( ulong j = 0; j < fd_quic_stream_map_slot_cnt( conn->stream_map ); ++j ) {
        if( conn->stream_map[j].stream_id != FD_QUIC_STREAM_ID_UNUSED ) {
          fd_quic_stream_map_remove( conn->stream_map, &conn->stream_map[j] );
          removed = 1;
          j--; /* retry this entry */
        }
      }
      if( !removed ) {
        FD_LOG_WARNING(( "None removed. Remain: %lu",
              (ulong)fd_quic_stream_map_key_cnt( conn->stream_map ) ));
        break;
      }
    }
  }

  /* destroy keys */
  fd_quic_free_keys( &conn->keys[0][0] );
  fd_quic_free_keys( &conn->keys[1][0] );
  fd_quic_free_keys( &conn->keys[2][0] );
  fd_quic_free_keys( &conn->keys[3][0] );
  fd_quic_free_keys( &conn->keys[0][1] );
  fd_quic_free_keys( &conn->keys[1][1] );
  fd_quic_free_keys( &conn->keys[2][1] );
  fd_quic_free_keys( &conn->keys[3][1] );

  /* free tls-hs */
  if( conn->tls_hs ) {
    fd_quic_tls_hs_delete( conn->tls_hs );
    conn->tls_hs = NULL;
  }

  /* put connection back in free list */
  conn->next   = state->conns;
  state->conns = conn;
  conn->state  = FD_QUIC_CONN_STATE_INVALID;

  /* free acks */
  for( ulong j = 0; j < 4; ++j ) {
    /* add whole list to free list */
    if( conn->acks_tx_end[j] ) {
      conn->acks_tx_end[j]->next = conn->acks_free;
      conn->acks_free            = conn->acks_tx[j];

      conn->acks_tx[j] = conn->acks_tx_end[j] = NULL;
    }
  }

  quic->metrics.conn_active_cnt--;

  /* clear keys */
  for( ulong j = 0U; j < 4U; ++j ) {
    for( ulong k = 0U; k < 2U; ++k ) {
      fd_memset( conn->keys[j][k].pkt_key, 0x42, sizeof( conn->keys[0][0].pkt_key ) );
      fd_memset( conn->keys[j][k].hp_key,  0x43, sizeof( conn->keys[0][0].hp_key  ) );
      fd_memset( conn->keys[j][k].iv,      0x45, sizeof( conn->keys[0][0].iv      ) );
      conn->keys[j][k].pkt_key_sz = 0;
      conn->keys[j][k].hp_key_sz  = 0;
      conn->keys[j][k].iv_sz      = 0;
    }
  }
  for( ulong k = 0U; k < 2U; ++k ) {
    fd_memset( conn->new_keys[k].pkt_key, 0x42, sizeof( conn->new_keys[0].pkt_key ) );
    fd_memset( conn->new_keys[k].hp_key,  0x43, sizeof( conn->new_keys[0].hp_key  ) );
    fd_memset( conn->new_keys[k].iv,      0x45, sizeof( conn->new_keys[0].iv      ) );
    conn->new_keys[k].pkt_key_sz = 0;
    conn->new_keys[k].hp_key_sz  = 0;
    conn->new_keys[k].iv_sz      = 0;
  }
}

fd_quic_conn_id_t
fd_quic_create_conn_id( fd_quic_t * quic ) {
  (void)quic;

  /* from rfc9000:
     Each endpoint selects connection IDs using an implementation-specific (and
       perhaps deployment-specific) method that will allow packets with that
       connection ID to be routed back to the endpoint and to be identified by
       the endpoint upon receipt. */
  /* this means we can generate a connection id with the property that it can
     be delivered to the same endpoint by flow control */
  /* TODO load balancing / flow steering */

  fd_quic_conn_id_t conn_id = { 8u, {0}, {0} };

  fd_quic_crypto_rand( conn_id.conn_id, 8u );

  return conn_id;
}

fd_quic_conn_t *
fd_quic_connect( fd_quic_t *  quic,
                 uint         dst_ip_addr,
                 ushort       dst_udp_port,
                 char const * sni ) {

  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* create conn ids for us and them
     client creates connection id for the peer, peer immediately replaces it */
  fd_quic_conn_id_t our_conn_id  = fd_quic_create_conn_id( quic );
  fd_quic_conn_id_t peer_conn_id = fd_quic_create_conn_id( quic );

  fd_quic_conn_t * conn = fd_quic_conn_create(
      quic,
      &our_conn_id,
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

  fd_quic_transport_params_t * tp = &state->transport_params;

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
  tp->initial_source_connection_id_len     = our_conn_id.sz;

  /* validate transport parameters */

  if( !fd_quic_transport_params_validate( tp ) ) {
    FD_LOG_WARNING(( "fd_quic_transport_params_validate failed" ));
    goto fail_conn;
  }

  /* Encode transport params to be sent to peer */

  uchar transport_params_raw[ FD_QUIC_TRANSPORT_PARAMS_RAW_SZ ];
  ulong tp_rc = fd_quic_encode_transport_params(
      transport_params_raw,
      FD_QUIC_TRANSPORT_PARAMS_RAW_SZ,
      tp );
  if( FD_UNLIKELY( tp_rc == FD_QUIC_ENCODE_FAIL ) ) {
    /* FIXME log error in counters */
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_encode_transport_params failed" )) );
    goto fail_conn;
  }

  ulong transport_params_raw_sz = tp_rc;

  /* Create a TLS handshake */

  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
      state->tls,
      (void*)conn,
      0 /*is_server*/,
      sni,
      transport_params_raw,
      transport_params_raw_sz );
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

  fd_quic_crypto_suite_t *suite =
          &state->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];
  if (FD_UNLIKELY(fd_quic_gen_initial_secret_and_keys(suite, conn, &peer_conn_id)) == FD_QUIC_FAILED)
  {
    fd_quic_conn_close(conn, FD_QUIC_CONN_REASON_CRYPTO_BASE);
    conn->state = FD_QUIC_CONN_STATE_DEAD;
    quic->metrics.conn_err_tls_fail_cnt++;
    quic->metrics.conn_aborted_cnt++;
    goto fail_tls_hs;
  }

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
                     fd_quic_conn_id_t const * our_conn_id,
                     fd_quic_conn_id_t const * peer_conn_id,
                     uint                      dst_ip_addr,
                     ushort                    dst_udp_port,
                     int                       server,
                     uint                      version ) {

  fd_quic_config_t * config = &quic->config;
  fd_quic_state_t *  state  = fd_quic_get_state( quic );

  /* fetch top of connection free list */
  fd_quic_conn_t * conn = state->conns;
  if( FD_UNLIKELY( !conn ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_conn_create failed: no free conn slots" )) );
    quic->metrics.conn_err_no_slots_cnt++;
    return NULL;
  }

  /* insert into connection map */
  fd_quic_conn_entry_t * insert_entry =
    fd_quic_conn_map_insert( state->conn_map, our_conn_id );

  /* if insert failed (should be impossible) fail, and do not remove connection
     from free list */
  if( FD_UNLIKELY( insert_entry == NULL ) ) {
    FD_LOG_WARNING(( "fd_quic_conn_create failed: failed to register new conn ID" ));
    return NULL;
  }

  /* set connection map insert_entry to new connection */
  insert_entry->conn = conn;

  /* remove from free list */
  state->conns = conn->next;
  conn->next   = NULL;

  /* if conn not marked free, skip */
  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_INVALID ) ) {
    FD_LOG_WARNING(( "conn %p not free, this is a bug", (void *)conn ));
    return NULL;
  }

  conn->next_service_time   = fd_quic_now( quic );
  conn->sched_service_time  = ~0UL;

  /* immediately schedule it */
  fd_quic_schedule_conn( conn );

  /* initialize connection members */
  conn->quic                = quic;
  conn->server              = server;
  conn->established         = 0;
  conn->version             = version;
  conn->called_conn_new     = 0;
  fd_memset( &conn->our_conn_id[0], 0, sizeof( conn->our_conn_id ) );
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
  conn->tx_max_datagram_sz  = FD_QUIC_INITIAL_PAYLOAD_SZ_MAX;
  conn->handshake_complete  = 0;
  conn->handshake_done_send = 0;
  conn->tls_hs              = NULL; /* created later */

  /* initial max_streams */

  if( server ) {
    /* we are the server, so start client-initiated at our max-concurrent,
       and server-initiated at 0 peer will advertise its configured maximum */
    conn->max_streams[ 0x00 ] = quic->limits.stream_cnt[ 0x00 ];  /* 0x00 Client-Initiated, Bidirectional */
    conn->max_streams[ 0x01 ] = 0;                                /* 0x01 Server-Initiated, Bidirectional */
    conn->max_streams[ 0x02 ] = quic->limits.stream_cnt[ 0x02 ];  /* 0x02 Client-Initiated, Unidirectional */
    conn->max_streams[ 0x03 ] = 0;                                /* 0x03 Server-Initiated, Unidirectional */
  } else {
     /* we are the client, so start server-initiated at our max-concurrent,
        and client-initiated at 0 peer will advertise its configured maximum */
    conn->max_streams[ 0x00 ] = 0;                                /* 0x00 Client-Initiated, Bidirectional */
    conn->max_streams[ 0x01 ] = quic->limits.stream_cnt[ 0x01 ];  /* 0x01 Server-Initiated, Bidirectional */
    conn->max_streams[ 0x02 ] = 0;                                /* 0x02 Client-Initiated, Unidirectional */
    conn->max_streams[ 0x03 ] = quic->limits.stream_cnt[ 0x03 ];  /* 0x03 Server-Initiated, Unidirectional */
  }

  /* conn->streams initialized inside fd_quic_conn_new */

  /* points to free tx space */
  conn->tx_ptr = conn->tx_buf;
  conn->tx_sz  = sizeof( conn->tx_buf );

  fd_memset( &conn->suites[0], 0, sizeof( conn->suites ) );

  /* rfc specifies TLS_AES_128_GCM_SHA256_ID for the suite for initial
     secrets and keys */
  conn->suites[ fd_quic_enc_level_initial_id ]
   = &state->crypto_ctx->suites[ TLS_AES_128_GCM_SHA256_ID ];

  /* stream metadata */
  conn->next_stream_id[0] = 0;
  conn->next_stream_id[1] = 1;
  conn->next_stream_id[2] = 2;
  conn->next_stream_id[3] = 3;

  /* start at our max, peer is allowed to lower */
  conn->max_concur_streams = (uint)(
      quic->limits.stream_cnt[ 0 ] +
      quic->limits.stream_cnt[ 1 ] +
      quic->limits.stream_cnt[ 2 ] +
      quic->limits.stream_cnt[ 3 ] );

  /* array: current number of streams by type is zero */
  fd_memset( &conn->num_streams, 0, sizeof( conn->num_streams ) );

  /* initialize streams */
  FD_QUIC_STREAM_LIST_SENTINEL( conn->unused_streams );
  FD_QUIC_STREAM_LIST_SENTINEL( conn->send_streams );
  ulong tot_num_streams = conn->tot_num_streams;
  for( ulong j = 0; j < tot_num_streams; ++j ) {
    /* insert into unused list */
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->unused_streams, conn->streams[j] );
    conn->streams[j]->stream_flags = 0;
  }

  /* initialize packet metadata */
  ulong num_pkt_meta = conn->num_pkt_meta;

  /* initialize the pkt_meta pool with data */
  fd_quic_pkt_meta_pool_init( &conn->pkt_meta_pool, conn->pkt_meta_mem, num_pkt_meta );

  /* clear peer transport parameters */
  fd_memset( &conn->peer_transport_params, 0, sizeof( conn->peer_transport_params ) );

  /* rfc9000: s12.3:
     Packet numbers in each packet space start at 0.
     Subsequent packets sent in the same packet number space
       MUST increase the packet number by at least 1
     rfc9002: s3
     It is permitted for some packet numbers to never be used, leaving intentional gaps. */
  fd_memset( conn->exp_pkt_number, 0, sizeof( conn->exp_pkt_number ) );
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
  conn->flags                = 0;
  conn->spin_bit             = 0;
  conn->upd_pkt_number       = 0;
  conn->base_timeout         = 0;

  /* initialize connection members */
  ulong our_conn_id_idx = 0;
  conn->our_conn_id[our_conn_id_idx] = *our_conn_id;
  conn->our_conn_id_cnt++;
  /* start with minimum supported max datagram */
  /* peers may allow more */
  conn->tx_max_datagram_sz = FD_QUIC_INITIAL_PAYLOAD_SZ_MAX;

  /* initial source connection id */
  conn->initial_source_conn_id = *our_conn_id;

  /* peer connection id */
  ulong peer_idx = 0;
  conn->peer[ peer_idx ].conn_id      = *peer_conn_id;
  conn->peer[ peer_idx ].net.ip_addr  = dst_ip_addr;
  conn->peer[ peer_idx ].net.udp_port = dst_udp_port;
  memset( &conn->peer[ peer_idx ].mac_addr, 0, 6 );
  conn->peer_cnt                      = 1;

  /* do routing */
  uchar  arp_mac_addr[6]  = {0};
  uint   arp_next_ip_addr = 0;
  uint   arp_ifindex      = 0;
  uint   arp_host_dst_ip  = fd_uint_bswap( dst_ip_addr );
  int arp_rtn = fd_ip_route_ip_addr( arp_mac_addr,
                                     &arp_next_ip_addr,
                                     &arp_ifindex,
                                     fd_quic_get_ip( quic ),
                                     arp_host_dst_ip );
  switch( arp_rtn ) {
    case FD_IP_SUCCESS:
      memcpy( &conn->peer[peer_idx].mac_addr, arp_mac_addr, 6 );
      conn->arp_status = FD_ARP_STATUS_RESOLVED;
      break;
    case FD_IP_PROBE_RQD:
      conn->arp_status = FD_ARP_STATUS_REQUIRED;
      break;

    case FD_IP_NO_ROUTE:
      FD_LOG_WARNING(( "No route to address 0x%08x", dst_ip_addr ));
      break;

    default:
      FD_LOG_WARNING(( "Unexpected routing for ip address 0x%08x. Code: %x",
            dst_ip_addr, arp_rtn ));
  }

  /* initialize other ack members */
  fd_memset( conn->acks_tx,     0, sizeof( conn->acks_tx ) );
  fd_memset( conn->acks_tx_end, 0, sizeof( conn->acks_tx_end ) );

  /* flow control params */
  conn->rx_max_data = state->initial_max_data; /* this is what we advertise initially */
  conn->tx_max_data = 0;

  /* no stream bytes sent or received yet */
  conn->tx_tot_data = 0;
  conn->rx_tot_data = 0;

  /* initial rtt */
  conn->rtt = (ulong)50e6;

  /* highest peer encryption level */
  conn->peer_enc_level = 0;

  /* idle timeout */
  conn->idle_timeout  = config->idle_timeout;
  conn->last_activity = fd_quic_now( quic );

  fd_memset( conn->exp_pkt_number, 0, sizeof( conn->exp_pkt_number ) );

  /* update metrics */
  quic->metrics.conn_active_cnt++;
  quic->metrics.conn_created_cnt++;

  /* return connection */
  return conn;
}

extern inline FD_FN_PURE
int
fd_quic_handshake_complete( fd_quic_conn_t * conn );

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
fd_quic_pkt_meta_retry( fd_quic_t *          quic,
                        fd_quic_conn_t *     conn,
                        int                  force ) {

  ulong now = fd_quic_now( quic );

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
  fd_quic_pkt_meta_pool_t * pool = &conn->pkt_meta_pool;

  while(1) {
    /* find earliest sent pkt_meta over all of the enc_levels */
    uint  enc_level      = ~0u;
    uint  peer_enc_level = conn->peer_enc_level;
    ulong expiry         = ~0ul;
    for( uint j = 0u; j < 4u; ++j ) {
      /* TODO this only checks the head of each enc_level
         assuming that pkt_meta is in time order. It IS
         is time order, but not expiry time. */
#if 0
      fd_quic_pkt_meta_t * pkt_meta = pool->sent[j].head;
      if( !pkt_meta ) continue;

      if( enc_level == ~0u || pkt_meta->expiry < expiry ) {
        enc_level = j;
        expiry    = pkt_meta->expiry;
      }
#else
      fd_quic_pkt_meta_t * pkt_meta = pool->sent[j].head;
      while( pkt_meta ) {
        if( enc_level == ~0u || pkt_meta->expiry < expiry ) {
          enc_level = j;
          expiry    = pkt_meta->expiry;
        }
        if( enc_level < peer_enc_level ) break;
        pkt_meta = pkt_meta->next;
      }
      if( enc_level != ~0u ) break;
#endif
    }

    if( enc_level == ~0u ) return;

    if( force ) {
      /* we're forcing, quit when we've freed enough */
      if( cnt_freed >= min_freed ) return;
    } else {
      /* not forcing, so quit if nothing has expired */
      if( expiry > now ) {
        return;
      }
    }

    fd_quic_pkt_meta_list_t * sent     = &pool->sent[enc_level];
    fd_quic_pkt_meta_t *      pkt_meta = sent->head;
    fd_quic_pkt_meta_t *      prior    = NULL; /* prior is always null, since we always look at head */

    /* already moved to another enc_level */
    if( enc_level < peer_enc_level ) {
      /* free pkt_meta */

      /* treat the original packet as-if it were ack'ed */
      fd_quic_reclaim_pkt_meta( conn,
                                pkt_meta,
                                enc_level );

      /* remove from list */
      fd_quic_pkt_meta_remove( sent, prior, pkt_meta );

      /* put pkt_meta back in free list */
      fd_quic_pkt_meta_deallocate( pool, pkt_meta );

      cnt_freed++;

      continue;
    }

    uint  pn_space        = fd_quic_enc_level_to_pn_space( enc_level );
    ulong pkt_number      = pkt_meta->pkt_number;

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
    if( flags & FD_QUIC_PKT_META_FLAGS_STREAM             ) {
      /* set the stream in question to resend the data */
      ulong stream_id = pkt_meta->stream_id;
      ulong offset    = pkt_meta->range.offset_lo;

      /* find the stream in the stream map */
      fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream_id, NULL );
      if( FD_LIKELY( stream_entry && stream_entry->stream->stream_id == stream_id ) ) {
        fd_quic_stream_t * stream = stream_entry->stream;

        /* do not try sending data that has been acked */
        offset = fd_ulong_max( offset, stream->tx_buf.tail );

        /* any data left to retry? */
        if( FD_LIKELY( offset < stream->tx_sent ) ) {
          /* move tx_sent back to calculated offset */
          stream->tx_sent = offset;

          /* if flags==0, the stream is not in the send list */
          if( !FD_QUIC_STREAM_ACTION( stream ) ) {
            /* insert into send list */
            FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, stream );
          }

          /* set the data to go out on the next packet */
          stream->stream_flags   |= FD_QUIC_STREAM_FLAGS_UNSENT; /* we have unsent data */
          stream->upd_pkt_number  = FD_QUIC_PKT_NUM_PENDING;
        }
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_HS_DONE            ) {
      /* do we need to resend the handshake done flag? */
      conn->handshake_done_send = 1;
      conn->upd_pkt_number      = FD_QUIC_PKT_NUM_PENDING;
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_MAX_DATA           ) {
      /* set max_data to be sent only if unacked */
      if( conn->rx_max_data_ackd < conn->rx_max_data ) {
        conn->flags         |= FD_QUIC_CONN_FLAGS_MAX_DATA;
        conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA    ) {
      /* we don't have the stream id for the max_stream_data stream
         TODO track acked_max_stream_data by stream */

      /* sending all isn't harmful to the state of the connection
         but it is slow

         This will be fixed by reorg of pkt_meta */

      ulong tot_num_streams = conn->tot_num_streams;
      for( ulong j = 0u; j < tot_num_streams; ++j ) {
        fd_quic_stream_t * stream = conn->streams[j];

        /* was this stream sent on the given packet number */
        if( stream->stream_id != FD_QUIC_STREAM_ID_UNUSED &&
            stream->upd_pkt_number == pkt_number ) {
          /* if flags==0, the stream is not in the send list */
          if( !FD_QUIC_STREAM_ACTION( stream ) ) {
            /* insert */
            FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, stream );
          }

          stream->stream_flags  |= FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
          stream->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
        }
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR ) {
      /* set the data to go out on the next packet */
      conn->flags          |= FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR;
      conn->upd_pkt_number  = FD_QUIC_PKT_NUM_PENDING;
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_BIDIR  ) {
      /* set the data to go out on the next packet */
      conn->flags          |= FD_QUIC_CONN_FLAGS_MAX_STREAMS_BIDIR;
      conn->upd_pkt_number  = FD_QUIC_PKT_NUM_PENDING;
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_ACK                ) {
      /* find the acks from the given packet */
      ulong pkt_number = pkt_meta->pkt_number;

      /* get the next packet number to resend the acks */
      ulong next_pkt_number = conn->pkt_number[pn_space];

      /* iterate thru the acks */
      fd_quic_ack_t * cur_ack = conn->acks_tx[enc_level];
      while( cur_ack ) {
        //if( cur_ack->tx_pkt_number > pkt_number ) break;

        if( cur_ack->tx_pkt_number == pkt_number ) {
          cur_ack->tx_pkt_number = next_pkt_number;
          cur_ack->tx_time       = now + 1u;

          /* mark as unsent, and add mandatory flag */
          cur_ack->flags         = (uchar)( ( cur_ack->flags & ~FD_QUIC_ACK_FLAGS_SENT )
                                                             |  FD_QUIC_ACK_FLAGS_MANDATORY );
        }

        cur_ack = cur_ack->next;
      }
    }
    if( flags & FD_QUIC_PKT_META_FLAGS_CLOSE              ) {
      conn->flags &= ~FD_QUIC_CONN_FLAGS_CLOSE_SENT;
      conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    }

    /* reschedule to ensure the data gets processed */
    fd_quic_reschedule_conn( conn, 0 );

    /* free pkt_meta */

    /* remove from list */
    fd_quic_pkt_meta_remove( sent, prior, pkt_meta );

    /* put pkt_meta back in free list */
    fd_quic_pkt_meta_deallocate( pool, pkt_meta );

    cnt_freed++;
  }
}

/* reclaim resources associated with packet metadata
   this is called in response to received acks */
void
fd_quic_reclaim_pkt_meta( fd_quic_conn_t *     conn,
                          fd_quic_pkt_meta_t * pkt_meta,
                          uint                 enc_level ) {

  uint            flags      = pkt_meta->flags;
  ulong           pkt_number = pkt_meta->pkt_number;
  fd_quic_range_t range      = pkt_meta->range;

  if( FD_UNLIKELY( flags & FD_QUIC_PKT_META_FLAGS_KEY_UPDATE ) ) {
    /* what key phase was used for packet? */
    uint pkt_meta_key_phase = !!( flags & FD_QUIC_PKT_META_FLAGS_KEY_PHASE );

    if( pkt_meta_key_phase != conn->key_phase ) {
      /* key update was acknowledged
         free old keys, and replace with new ones */
      fd_quic_free_pkt_keys( &conn->keys[enc_level][0] );
      fd_quic_free_pkt_keys( &conn->keys[enc_level][1] );

      /* TODO improve this code */
#     define COPY_KEY(SERVER,KEY)                         \
        fd_memcpy( &conn->keys[enc_level][SERVER].KEY[0], \
                   &conn->new_keys[SERVER].KEY[0],        \
                   sizeof( conn->keys[enc_level][0].KEY ) )
      COPY_KEY(0,pkt_key);
      COPY_KEY(0,iv);
      COPY_KEY(1,pkt_key);
      COPY_KEY(1,iv);
      conn->keys[enc_level][0].pkt_cipher_ctx = conn->new_keys[0].pkt_cipher_ctx;
      conn->keys[enc_level][1].pkt_cipher_ctx = conn->new_keys[1].pkt_cipher_ctx;
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

      FD_LOG_DEBUG(( "key update completed" ));

      /* TODO still need to add code to initiate key update */
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_HS_DATA ) {
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

      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
      while( hs_data && hs_data->offset + hs_data->data_sz <= hs_ackd_bytes ) {
        fd_quic_tls_pop_hs_data( conn->tls_hs, (int)enc_level );
        hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
      }
    } else {
      conn->hs_sent_bytes[enc_level] =
          fd_ulong_min( conn->hs_sent_bytes[enc_level], hs_ackd_bytes );
      conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_HS_DONE ) {
    fd_quic_tls_hs_data_t * hs_data   = NULL;

    hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
    while( hs_data ) {
      fd_quic_tls_pop_hs_data( conn->tls_hs, (int)enc_level );
      hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_DATA ) {
    ulong max_data_ackd = 0UL;
    for( ulong j = 0UL; j < pkt_meta->var_sz; ++j ) {
      if( pkt_meta->var[j].key.type  == FD_QUIC_PKT_META_TYPE_OTHER &&
          pkt_meta->var[j].key.flags == FD_QUIC_PKT_META_FLAGS_MAX_DATA ) {
        max_data_ackd = pkt_meta->var[j].value;
      }
    }

    /* ack can only increase max_data_ackd */
    max_data_ackd = fd_ulong_max( max_data_ackd, conn->rx_max_data_ackd );

    /* max_data_ackd > rx_max_data is a protocol violation */
    if( FD_UNLIKELY( max_data_ackd > conn->rx_max_data ) ) {
      /* this is a protocol violation, so inform the peer */
      fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return;
    }

    /* clear flag only if acked value == current value */
    if( FD_LIKELY( max_data_ackd == conn->rx_max_data ) ) {
      conn->flags &= ~FD_QUIC_CONN_FLAGS_MAX_DATA;
    }

    /* set the ackd value */
    conn->rx_max_data_ackd = max_data_ackd;
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_BIDIR ) {
    conn->flags &= ~FD_QUIC_CONN_FLAGS_MAX_STREAMS_BIDIR;
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR ) {
    conn->flags &= ~FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR;
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA ) {
    /* find stream */
    ulong                  stream_id    = pkt_meta->stream_id;
    fd_quic_stream_t *     stream       = NULL;
    fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream_id, NULL );
    if( FD_LIKELY( stream_entry &&
          ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) == 0 ) ) {
      stream = stream_entry->stream;
      if( FD_LIKELY( stream->stream_flags & FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA ) ) {
        stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
        if( !FD_QUIC_STREAM_ACTION( stream ) ) {
          /* remove from list */
          FD_QUIC_STREAM_LIST_REMOVE( stream );
        }
      }
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
    /* find stream */
    ulong                  stream_id    = pkt_meta->stream_id;
    fd_quic_stream_t *     stream       = NULL;
    fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream_id, NULL );
    if( FD_LIKELY( stream_entry &&
          ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) == 0 ) ) {
      stream = stream_entry->stream;

      ulong tx_tail = stream->tx_buf.tail;
      ulong tx_sent = stream->tx_sent;

      /* ignore bytes which were already acked */
      if( range.offset_lo < tx_tail ) range.offset_lo = tx_tail;

      /* if they ack bytes we didn't send, that's a protocol error */
      /* TODO ensure this is the correct reason */
      if( range.offset_hi > tx_sent ) {
        FD_LOG_WARNING(( "Protocol violation: acked unsent bytes" ));
        FD_LOG_WARNING(( "offset_hi: %lu  tx_sent: %lu", range.offset_hi, tx_sent ));
        fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      } else {
        /* did they ack the first byte in the range? */
        if( FD_LIKELY( range.offset_lo == tx_tail ) ) {
          /* then simply move the tail up */
          tx_tail = range.offset_hi;
        } else {
          /* set appropriate bits in tx_ack */
          /* TODO optimize this */
          ulong   tx_mask  = stream->tx_buf.cap - 1ul;
          ulong   cnt      = range.offset_hi - range.offset_lo;
          uchar * tx_ack   = stream->tx_ack;
          for( ulong j = 0ul; j < cnt; ) {
            ulong k = ( j + range.offset_lo ) & tx_mask;
            if( ( k & 7ul ) == 0ul && j + 8ul <= cnt ) {
              /* set whole byte */
              tx_ack[k>>3ul] = 0xffu;

              j += 8ul;
            } else {
              /* compiler is not smart enough to know ( 1u << ( k & 7u ) ) fits in a uchar */
              tx_ack[k>>3ul] |= (uchar)( 1ul << ( k & 7ul ) );
              j++;
            }
          }

          /* determine whether tx_tail may be moved up */
          for( ulong j = tx_tail; j < tx_sent; ) {
            ulong k = j & tx_mask;

            /* can we skip a whole byte? */
            if( ( k & 7ul ) == 0ul && j + 8ul <= tx_sent && tx_ack[k>>3ul] == 0xffu ) {
              tx_ack[k>>3ul] = 0u;
              tx_tail       += 8ul;

              j += 8ul;
            } else {
              tx_ack[k>>3ul] = (uchar)( tx_ack[k>>3ul] & ~( 1u << ( k & 7u ) ) );
              tx_tail++;
              j++;
            }
          }
        }

        /* for convenience */
        uint state_mask = FD_QUIC_STREAM_STATE_TX_FIN | FD_QUIC_STREAM_STATE_RX_FIN;

        /* move up tail, and adjust to maintain circular queue invariants, and send
           max_data and max_stream_data, if necessary */
        if( tx_tail > stream->tx_buf.tail ) {
          stream->tx_buf.tail = tx_tail;

          /* if we have data to send, reschedule */
          if( fd_quic_buffer_used( &stream->tx_buf ) ) {
            fd_quic_reschedule_conn( conn, 0 );
          } else {
            /* if no data to send, check whether fin bits are set */
            uint state_mask = FD_QUIC_STREAM_STATE_TX_FIN | FD_QUIC_STREAM_STATE_RX_FIN;
            if( ( stream->state & state_mask ) == state_mask ) {
              /* fd_quic_stream_free also notifies the user */
              fd_quic_stream_free( conn->quic, conn, stream, FD_QUIC_NOTIFY_END );
            }
          }
        } else if( tx_tail == stream->tx_buf.tail &&
            ( stream->state & state_mask ) == state_mask ) {
          /* fd_quic_stream_free also notifies the user */
          fd_quic_stream_free( conn->quic, conn, stream, FD_QUIC_NOTIFY_END );
        }

        /* we could retransmit (timeout) the bytes which have not been acked (by implication) */
      }
    }
  }

  /* max_stream_data */
  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA ) {
#if 0
    ulong               tot_num_streams = conn->tot_num_streams;
    fd_quic_stream_t ** streams         = conn->streams;
    /* TODO avoid linear search here */
    for( ulong j = 0; j < tot_num_streams; ++j ) {
      fd_quic_stream_t * stream = streams[j];
      if( stream->upd_pkt_number == pkt_number ) {
        stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
        if( stream->stream_flags == 0 ) {
          /* stream must be in send_streams, so remove */
          FD_QUIC_STREAM_LIST_REMOVE( stream );
        }
      }
    }
#else
    fd_quic_stream_t * sentinel = conn->send_streams;
    fd_quic_stream_t * stream   = sentinel->next;
    while( !stream->sentinel ) {
      if( stream->upd_pkt_number == pkt_number ) {
        if( stream->stream_flags & FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA ) {
          stream->stream_flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
          if( !FD_QUIC_STREAM_ACTION( stream ) ) {
            /* stream must be in send_streams, so remove */
            FD_QUIC_STREAM_LIST_REMOVE( stream );
          }
        }
      }

      stream = stream->next;
    }
#endif
  }

  /* acks */
  if( flags & FD_QUIC_PKT_META_FLAGS_ACK ) {
    /* remove all acks with given packet number */
    fd_quic_ack_t * cur_ack = conn->acks_tx[enc_level];
    while( cur_ack ) {
      fd_quic_ack_t * next_ack = cur_ack->next;
      if( next_ack ) {
        if( next_ack->tx_pkt_number == pkt_number ) {
          /* remove next_ack */
          if( next_ack->next == NULL ) {
            /* next_ack is last, so update end */
            conn->acks_tx_end[enc_level] = cur_ack;
          }
          cur_ack->next = next_ack->next;

          /* put in free list */
          next_ack->next  = conn->acks_free;
          conn->acks_free = next_ack;
        }
      } else {
        break;
      }
      cur_ack = cur_ack->next;
    }
    /* head treated separately */
    cur_ack = conn->acks_tx[enc_level];
    if( cur_ack && cur_ack->tx_pkt_number == pkt_number ) {
        if( cur_ack->next == NULL ) {
          /* cur_ack is last, so update end */
          conn->acks_tx_end[enc_level] = NULL;
        }
        conn->acks_tx[enc_level] = cur_ack->next;

        /* add to free list */
        cur_ack->next   = conn->acks_free;
        conn->acks_free = cur_ack;
    }
  }
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
  fd_quic_pkt_meta_pool_t * pool     = &conn->pkt_meta_pool;
  fd_quic_pkt_meta_list_t * sent     = &pool->sent[enc_level];
  fd_quic_pkt_meta_t *      pkt_meta = sent->head;
  fd_quic_pkt_meta_t *      prior    = NULL;
  while( pkt_meta ) {
    if( pkt_meta->pkt_number < lo ) {
      /* go to next, keeping track of prior */
      prior    = pkt_meta;
      pkt_meta = pkt_meta->next;
      continue;
    }

    /* keep pkt_meta->next for later */
    fd_quic_pkt_meta_t * pkt_meta_next = pkt_meta->next;

    /* packet number is in range, so reclaim the resources */
    if( pkt_meta->pkt_number <= hi ) {
      fd_quic_reclaim_pkt_meta( conn,
                                pkt_meta,
                                enc_level );

      /* remove from list */
      fd_quic_pkt_meta_remove( sent, prior, pkt_meta );

      /* put pkt_meta back in free list */
      fd_quic_pkt_meta_deallocate( pool, pkt_meta );

      /* we removed one, so keep prior the same and move pkt_meta up */
      pkt_meta = pkt_meta_next;
      continue;
    }

    prior    = pkt_meta;
    pkt_meta = pkt_meta_next;
  }
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
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
    return FD_QUIC_PARSE_FAIL;
  }

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
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
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
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    /* process ack range */
    fd_quic_process_ack_range( context.conn, enc_level, cur_pkt_number - skip, length );

    /* Find the next lowest processed and acknowledged packet number
       This should get us to the next lowest processed and acknowledged packet
       number */
    cur_pkt_number -= skip + length;

    p += rc;
  }

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
fd_quic_frame_handle_ack_range_frag(
    void * context,
    fd_quic_ack_range_frag_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_ecn_counts_frag(
    void * context,
    fd_quic_ecn_counts_frag_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
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
    void * context,
    fd_quic_stop_sending_frame_t * data,
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

void
fd_quic_stream_reclaim( fd_quic_conn_t * conn ) {
  for( ulong stream_type = 0; stream_type < 4; ++stream_type ) {
    ulong stream_cnt     = conn->quic->limits.stream_cnt[stream_type];
    ulong next_stream_id = conn->max_streams[stream_type] * 4UL + stream_type;
    ulong min_stream_id  = 0;
    if( next_stream_id > stream_cnt * 4UL ) min_stream_id = next_stream_id - stream_cnt * 4UL;

    for( ulong j = min_stream_id; j < next_stream_id; j += 4UL ) {
      ulong stream_id = j;

      /* look up stream_id in stream_map */
      fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream_id, NULL );

      /* can only remove the lowest numbered stream id */

      /* either a stream_id that hasn't been used, or one that's currently active */
      if( stream_entry == NULL ||
          ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) == 0 ) break;

      fd_quic_stream_t * stream = stream_entry->stream;

      /* remove the stream_id from the map */
      fd_quic_stream_map_remove( conn->stream_map, stream_entry );

      stream->stream_id = FD_QUIC_STREAM_ID_UNUSED;

      /* idempotent */
      FD_QUIC_STREAM_LIST_REMOVE( stream );

      /* insert into unused list */
      FD_QUIC_STREAM_LIST_INSERT_AFTER( conn->unused_streams, stream );
      stream->stream_flags = 0;

      /* track current number of streams */
      conn->num_streams[stream_type]--;

      /* was the stream initiated by the peer */
      if( (uint)( stream_type & 1u ) == (uint)!conn->server ) {
	conn->max_streams[stream_type]++; /* allows for one more stream */

	/* trigger frame to increase max_streams for peer */
	uint flag     = ( stream_id & 2u ) ? FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR
					   : FD_QUIC_CONN_FLAGS_MAX_STREAMS_BIDIR;
	conn->flags         |= flag;
	conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
      }
    }
  }
}

void
fd_quic_stream_free( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_stream_t * stream, int code ) {
  /* TODO rename FD_QUIC_NOTIFY_END to FD_QUIC_STREAM_NOTIFY_END et al */
  fd_quic_cb_stream_notify( quic, stream, stream->context, code );

  ulong stream_id   = stream->stream_id;

  /* reclaim removes it from stream map */
  fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( conn->stream_map, stream_id, NULL );
  if( FD_LIKELY( stream_entry ) ) {
    stream_entry->stream->stream_flags = FD_QUIC_STREAM_FLAGS_DEAD;
  } else {
    FD_LOG_WARNING(( "stream %lu not found in stream map", (ulong)stream_id ));
  }

  /* remove from send_streams */
  if( FD_QUIC_STREAM_ACTION( stream ) ) {
    FD_QUIC_STREAM_LIST_REMOVE( stream );
  }
  stream->stream_flags = FD_QUIC_STREAM_FLAGS_DEAD;

  fd_quic_stream_reclaim( conn );
}

static ulong
fd_quic_frame_handle_stream_frame(
    void *                       vp_context,
    fd_quic_stream_frame_t *     data,
    uchar const *                p,
    ulong                        p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;

  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* offset field is optional, implied 0 */
  ulong offset    = data->offset_opt ? data->offset : 0;
  ulong stream_id = data->stream_id;
  uint  type      = stream_id & 0x03u;

  ulong data_sz   = data->length_opt ? data->length : p_sz;

  /* quick sanity check */
  if( FD_UNLIKELY( data_sz > p_sz ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* TODO consider storing min_stream_id instead of recalculating it */
  ulong stream_type    = stream_id & 3UL;
  ulong stream_cnt     = context.quic->limits.stream_cnt[stream_type];
  ulong next_stream_id = context.conn->max_streams[stream_type] * 4UL + stream_type;
  ulong min_stream_id  = 0;
  if( next_stream_id > stream_cnt * 4UL ) min_stream_id = next_stream_id - stream_cnt * 4UL;

  /* stream id is an old one, assume a retransmit and ack */
  if( FD_UNLIKELY( stream_id < min_stream_id ) ) {
    return data_sz;
  }

  /* find stream */
  fd_quic_stream_t *     stream       = NULL;
  fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( context.conn->stream_map, stream_id, NULL );

  if( stream_entry ) {
    /* stream is dead. Assume a retransmit, and ack */
    if( FD_UNLIKELY( ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) != 0 ) ) {
      return data_sz;
    }

    stream = stream_entry->stream;
  } else {
    /* not found, get unused stream */
    fd_quic_stream_t * sentinel = context.conn->unused_streams;

    stream = sentinel->next;

    if( FD_LIKELY( !stream->sentinel ) ) {
      ulong max_stream_id = ( context.conn->max_streams[type] << 2u ) + type;
      if( FD_UNLIKELY( stream_id > max_stream_id ) ) {
        fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );

        /* since we're terminating the connection, don't parse more */
        return FD_QUIC_PARSE_FAIL;
      }

      /* new stream - peer initiated */

      /* initialize stream members */

      fd_quic_stream_init( stream );

      /* we need to know if client-initiated or server-initiated
         we know peer initiated, so: */
      uint initiator = !context.conn->server;

      /* client chosen stream id must match type */
      uint stream_id_initiator = stream_id & 1u;
      if( FD_UNLIKELY( stream_id_initiator != initiator ) ) {
        FD_LOG_WARNING(( "Protocol violation: Peer requested invalid stream id" ));
        fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );

        /* since we're terminating the connection, don't parse more */
        return FD_QUIC_PARSE_FAIL;
      }

      /* bidirectional? */
      uint bidir = !( ( stream_id >> 1u ) & 1u );

      /* if unidir, we can't send - since peer initiated */
      /* if bidir we can only send up to the peer's advertised limit */
      ulong tx_max_stream_data = bidir ?
                  context.conn->tx_initial_max_stream_data_bidi_local : 0;

      stream->conn        = context.conn;

      stream->context     = NULL; /* TODO where do we get this from? */

      stream->tx_buf.head = 0; /* first unused byte of tx_buf */
      stream->tx_buf.tail = 0; /* first unacked (used) byte of tx_buf */
      stream->tx_sent     = 0; /* first unsent byte of tx_buf */
      memset( stream->tx_ack, 0, stream->tx_buf.cap >> 3ul );

      stream->stream_flags = 0UL;
      stream->state        = bidir ? 0u : FD_QUIC_STREAM_STATE_TX_FIN;

      /* flow control */
      stream->tx_max_stream_data = tx_max_stream_data;
      stream->tx_tot_data        = 0;
      stream->tx_last_byte       = 0;

      stream->rx_max_stream_data = context.quic->config.initial_rx_max_stream_data;
      stream->rx_tot_data        = 0;

      stream->upd_pkt_number     = 0;

      /* insert into stream map */
      fd_quic_stream_map_t * entry = fd_quic_stream_map_insert( context.conn->stream_map, stream_id );
      if( FD_UNLIKELY( !entry ) ) {
        /* stream map is sized to allow all concurrent streams with extra space for efficiency
           so this should never happen */
        FD_LOG_WARNING(( "no space in stream map" ));

        /* abort connection */
        fd_quic_conn_error( stream->conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );

        return FD_QUIC_PARSE_FAIL;
      }

      entry->stream = stream;

      /* remove from head of unused streams list */
      fd_quic_conn_t * conn = context.conn;
      FD_QUIC_STREAM_LIST_REMOVE( stream );

      stream->stream_id   = stream_id;

      /* track current number of streams */
      conn->num_streams[type]++;

      fd_quic_cb_stream_new( context.quic, stream, bidir ? FD_QUIC_TYPE_BIDIR : FD_QUIC_TYPE_UNIDIR );
    } else {
      /* no free streams - concurrent max should handle this */
      FD_LOG_WARNING(( "insufficient space for incoming stream, yet concurrent max not exceeded" ));

      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );

      /* since we're terminating the connection, don't parse more */
      return FD_QUIC_PARSE_FAIL;
    }
  }

  /* A receiver MUST close the connection with an error of type FLOW_CONTROL_ERROR if the sender
     violates the advertised connection or stream data limits */
  if (stream->rx_max_stream_data < offset + data_sz) {
    FD_LOG_WARNING(( "peer exceeded advertised stream data limit" ));
    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );
    return FD_QUIC_PARSE_FAIL;
  }

  /* TODO pass the fin bit to the user here? */
  /* or provide in API */

  /* TODO if fin bit set, store the final size */

  /* determine whether any of these bytes were already received
     or whether these bytes are out of order */

  /* get connection */
  fd_quic_conn_t * conn = stream->conn;

  ulong exp_offset = stream->rx_tot_data; /* we expect the next byte */

  /* do we have at least one byte we can deliver? */
  if( FD_LIKELY( offset <= exp_offset && offset + data_sz > exp_offset ) ) {
    if( FD_UNLIKELY( stream->state & FD_QUIC_STREAM_STATE_RX_FIN ) ) {
      /* this stream+direction was already FIN... protocol error */
      /* TODO might be a stream error instead */
      FD_LOG_WARNING(( "Protocol violation: already FIN" ));
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    ulong skip = exp_offset - offset; /* skip already delivered bytes */

    ulong delivered = data_sz - skip;

    fd_quic_cb_stream_receive(
        context.quic,
        stream,
        stream->context,
        p + skip,
        delivered,
        exp_offset,
        data->fin_opt
    );

    /* send a max data update
       must do this before the stream-fin flags are checked */
    conn->rx_max_data   += delivered;
    conn->flags         |= FD_QUIC_CONN_FLAGS_MAX_DATA;
    conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;

    /* ensure we ack the packet, and send any max data or max stream data
       frames */
    fd_quic_reschedule_conn( context.conn, 0 );

    /* update data received */
    stream->rx_tot_data = exp_offset + delivered;
    conn->rx_tot_data  += delivered;

    /* should we reclaim the stream */
    if( data->fin_opt ) {
      stream->state |= FD_QUIC_STREAM_STATE_RX_FIN;
      if( stream->state & FD_QUIC_STREAM_STATE_TX_FIN ||
          stream->stream_id & ( FD_QUIC_TYPE_UNIDIR << 1u ) ) {
        fd_quic_stream_free( context.quic, conn, stream, FD_QUIC_NOTIFY_END );
        return data_sz;
      }
    }

    /* set max_data and max_data_frame to go out next packet */
    stream->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;

    if( !FD_QUIC_STREAM_ACTION( stream ) ) {
      /* going from 0 to nonzero, so insert into action list */
      FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, stream );
    }

    stream->stream_flags |= FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
  } else {
    if( offset > exp_offset ) {
      /* TODO technically "future" out of order bytes should be counted,
         and if within our published max_stream_data (and max_data) should be stored
         in a reorder buffer. */
      /* for now, we cancel the ack */
      context.pkt->ack_flag |= ACK_FLAG_CANCEL;
    } else if( offset == exp_offset && data->length == 0 && data->fin_opt ) {
      /* fin stream in zero-length packet */
      if( ~( stream->state & FD_QUIC_STREAM_STATE_RX_FIN ) ) {
        stream->state |= FD_QUIC_STREAM_STATE_RX_FIN;
        if( stream->state & FD_QUIC_STREAM_STATE_TX_FIN ||
            stream->stream_id & ( FD_QUIC_TYPE_UNIDIR << 1u ) ) {
          fd_quic_stream_free( context.quic, conn, stream, FD_QUIC_NOTIFY_END );
          return data_sz;
        }
      }
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

  return 0; /* no additional bytes consumed from buffer */
}

static ulong
fd_quic_frame_handle_max_stream_data(
    void *                      vp_context,
    fd_quic_max_stream_data_t * data,
    uchar const *               p,
    ulong                      p_sz ) {
  (void)p;
  (void)p_sz;
  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  ulong stream_id  = data->stream_id;

  /* find stream */
  fd_quic_stream_map_t * stream_entry = fd_quic_stream_map_query( context.conn->stream_map, stream_id, NULL );
  if( FD_UNLIKELY( !stream_entry ||
        ( stream_entry->stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) != 0 ) ) return 0;

  fd_quic_stream_t * stream = stream_entry->stream;

  ulong tx_max_stream_data  = stream->tx_max_stream_data;
  ulong new_max_stream_data = data->max_stream_data;

  /* max data is only allowed to increase the limit. Transgressing frames
     are silently ignored */
  stream->tx_max_stream_data = new_max_stream_data > tx_max_stream_data ? new_max_stream_data : tx_max_stream_data;

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
  context.conn->max_streams[type] = fd_ulong_max( data->max_streams, context.conn->max_streams[type] );

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

  /* TODO STREAMS_BLOCKED should be sent by client when it wants
     to use a new stream, but is unable to due to the max_streams
     value
     We can support this in the future, but the solana-tpu client
     does not currently use it */
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

  FD_DEBUG( FD_LOG_DEBUG(( "new_conn_id requested" )); )
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
  FD_DEBUG(
    printf( "%s:%d  retire_conn_id requested\n", __func__, (int)(__LINE__) ); fflush( stdout );
    )

  // fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  // /* ack-eliciting */
  // context.pkt->ack_flag |= ACK_FLAG_RQD;

  return FD_QUIC_PARSE_FAIL;
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
    FD_LOG_WARNING(( "Protocol violation: handshake done on wrong role" ));
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
    return FD_QUIC_PARSE_FAIL;
  }

  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) ) {
    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_PEER_CLOSE:
      case FD_QUIC_CONN_STATE_ABORT:
      case FD_QUIC_CONN_STATE_CLOSE_PENDING:
      case FD_QUIC_CONN_STATE_DEAD:
        /* connection closing... nothing to do */
        return 0;

      case FD_QUIC_CONN_STATE_ACTIVE:
        /* already active - probably received out of order */
        return 0;
    }

    /* either we treat this as a fatal error, or just warn
       if we don't tear down the connection we must move to ACTIVE */
    FD_LOG_WARNING(( "%s : handshake done frame received, but not in handshake complete state", __func__ ));
  }

  /* eliminate any remaining hs_data at application level */
  fd_quic_tls_hs_data_t * hs_data = NULL;

  int hs_enc_level = fd_quic_enc_level_appdata_id;
  hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, hs_enc_level );
  /* skip packets we've sent */
  while( hs_data ) {
    fd_quic_tls_pop_hs_data( conn->tls_hs, hs_enc_level );

    hs_data = fd_quic_tls_get_hs_data( conn->tls_hs, hs_enc_level );
  }

  /* we shouldn't be receiving this unless handshake is complete */
  conn->state = FD_QUIC_CONN_STATE_ACTIVE;

  /* user callback */
  fd_quic_cb_conn_hs_complete( conn->quic, conn );

  return 0;
}

static ulong
fd_quic_frame_handle_common_frag(
    void * context,
    fd_quic_common_frag_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  /* this callback is completely unused */
  /* TODO tag template to not generate code for this */
  return FD_QUIC_PARSE_FAIL;
}

/* initiate the shutdown of a connection
   may select a reason code */
void
fd_quic_conn_close( fd_quic_conn_t * conn, uint app_reason ) {
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

ulong
fd_quic_conn_get_pkt_meta_free_count( fd_quic_conn_t * conn ) {
  fd_quic_pkt_meta_t * pkt_meta = conn->pkt_meta_pool.free.head;
  ulong cnt = 0;
  while( pkt_meta ) {
    cnt++;
    pkt_meta = pkt_meta->next;
  }
  return cnt;
}
