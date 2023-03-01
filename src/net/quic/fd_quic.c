#include "fd_quic.h"
#include "fd_quic_private.h"

#include "fd_quic_proto.h"
#include "templ/fd_quic_transport_params.h"

#include <string.h>
#include <stdlib.h>

#include "templ/fd_quic_parse_util.h"
#include "../util/fd_net_util.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "fd_quic_proto.h"

/* define a priority queue for time based processing */
#define PRQ_NAME      service_queue
#define PRQ_T         fd_quic_event_t
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"

#if 0
#define DEBUG(...) __VA_ARGS__ fflush( stdout ); fflush( stderr );
#else
#define DEBUG(...)
#endif

#define QUIC_DISABLE_CRYPTO 0


/* TODO improve this map */
/* map of encryption levels to packet number space */
static uchar el2pn_map[] = { 0, 2, 1, 2 };
uint
fd_quic_enc_level_to_pn_space( uint enc_level ) {
  if( FD_UNLIKELY( enc_level >= 4 ) ) {
    FD_LOG_ERR(( "fd_quic_enc_level_to_pn_space callend with invalid enc_level" ));
  }
  return el2pn_map[enc_level];
}


/* This code is directly from rpc9000 A.3 */
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


/* reschedule a connection */
void
fd_quic_reschedule_conn( fd_quic_conn_t * conn, ulong timeout );


/* set a connection to aborted, and set a reason code */
void
fd_quic_conn_error( fd_quic_conn_t * conn, uint reason ) {
  if( FD_UNLIKELY( conn->state == FD_QUIC_CONN_STATE_DEAD ) ) return;

  FD_LOG_WARNING(( "Connection terminating with reason code %u", reason ));
  conn->state  = FD_QUIC_CONN_STATE_ABORT;
  conn->reason = reason;

  /* set connection to be serviced ASAP */
  fd_quic_t * quic = conn->quic;
  fd_quic_reschedule_conn( conn, quic->now_fn( quic->now_ctx ) + 1u );
}


fd_quic_conn_t *
fd_quic_create_connection( fd_quic_t *               quic,
                           fd_quic_conn_id_t const * our_conn_id,
                           fd_quic_conn_id_t const * peer_conn_id,
                           uint                      dst_ip_addr,
                           ushort                    dst_udp_port,
                           int                       server );


/* returns the enc level we should use for the next tx quic packet
   or all 1's if nothing to tx */
uint
fd_quic_tx_enc_level( fd_quic_conn_t * conn ) {
  uint enc_level = ~0u;

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
        } else {
          return fd_quic_enc_level_handshake_id;
        }
      }
  }

  /* Check for acks to send */

  /* TODO replace enc_level with pn_space for ack index
     not necessary until 0-rtt is supported */
  for( uint k = 0; k < 4; ++k ) {
    fd_quic_ack_t * cur_ack_head = conn->acks_tx[k];
    /* do we have any in the chain that are mandatory? */
    if( cur_ack_head                                      &&
        !( cur_ack_head->flags & FD_QUIC_ACK_FLAGS_SENT ) &&
        cur_ack_head->flags & FD_QUIC_ACK_FLAGS_MANDATORY ) {
      return k;
    }
  }

  /* Check for handshake data to send */
  fd_quic_tls_hs_data_t * hs_data   = NULL;

  for( uint i = 0; i < 4 && i < enc_level; ++i ) {
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
  if( FD_UNLIKELY( conn->handshake_done ) ) return fd_quic_enc_level_appdata_id;

  /* find stream data to send */
  fd_quic_stream_t ** streams = conn->streams;
  for( ulong j = 0; j < conn->tot_num_streams; ++j ) {
    if( streams[j]->tx_buf.head > streams[j]->tx_sent ) {
      return fd_quic_enc_level_appdata_id;
    }
  }

  uint pn_space = fd_quic_enc_level_to_pn_space( fd_quic_enc_level_appdata_id );

  if( conn->flags && conn->upd_pkt_number > conn->pkt_number[pn_space] ) {
    enc_level = fd_quic_enc_level_appdata_id;
  }

  return enc_level;
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


#if 0
void
breakpoint( int N, ... ) {
  va_list ap;
  va_start( ap, N ); // Requires the last fixed parameter (to get the address)
  for( int j=0; j < N; j++ ) {
    void * arg = va_arg( ap, void* ); // Requires the type to cast to. Increments ap to the next argument.
    __asm__( "nop" : "=r" (arg) : : "memory" );
  }
  va_end( ap );
}
#endif


/* handle single v1 frames */
/* returns bytes consumed */
ulong
fd_quic_handle_v1_frame( fd_quic_t *      quic,
                         fd_quic_conn_t * conn,
                         fd_quic_pkt_t *  pkt,
                         uchar const *    buf,
                         ulong            buf_sz,
                         void *           scratch ) {
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


/* declare callbacks from quic-tls into quic */
int
fd_quic_tls_cb_client_hello( fd_quic_tls_hs_t * hs,
                             void *             context );

int
fd_quic_tls_cb_handshake_data( fd_quic_tls_hs_t *    hs,
                               void *                context,
                               OSSL_ENCRYPTION_LEVEL enc_level,
                               uchar const *         data,
                               ulong                data_sz );

void
fd_quic_tls_cb_alert( fd_quic_tls_hs_t * hs,
                      void *             context,
                      int                alert );

void
fd_quic_tls_cb_secret( fd_quic_tls_hs_t *           hs,
                       void *                       context,
                       fd_quic_tls_secret_t const * secret );

void
fd_quic_tls_cb_handshake_complete( fd_quic_tls_hs_t * hs,
                                   void *             context  );


ulong fd_quic_align() {
  ulong align = alignof( fd_quic_t );
  align = fd_ulong_max( align, fd_quic_conn_align() );
  align = fd_ulong_max( align, fd_quic_conn_map_align() );
  align = fd_ulong_max( align, fd_quic_stream_align() );
  align = fd_ulong_max( align, alignof( fd_quic_conn_id_t ) );
  align = fd_ulong_max( align, fd_quic_conn_map_align() );
  align = fd_ulong_max( align, service_queue_align() );
  return align;
}


ulong fd_quic_footprint( fd_quic_config_t * config ) {
  ulong offs  = 0;
  ulong align = fd_quic_align();

  offs += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_t ), align );

  ulong conn_foot     = fd_quic_conn_footprint( config );
  ulong conn_foot_tot = config->max_concur_conns * conn_foot;
  offs += FD_QUIC_POW2_ALIGN( conn_foot_tot, align );

  /* make enough space for the hash map slots */
  ulong slot_cnt_bound = config->conn_id_sparsity * config->max_concur_conns * config->max_concur_conn_ids;
  int   lg_slot_cnt    = fd_ulong_find_msb( slot_cnt_bound - 1 ) + 1;
  offs += FD_QUIC_POW2_ALIGN( fd_quic_conn_map_footprint( lg_slot_cnt ), align );

  /* make enough space for the events priority queue */
  ulong event_queue_sz = service_queue_footprint( config->max_concur_conns + 1 );
  offs += FD_QUIC_POW2_ALIGN( event_queue_sz, align );

  return offs;
}

/* fd_quic_new

   create a new quic endpoint

   Args
     mem          the memory to use for the newly created quic object
                    must be aligned according to fd_quic_align( config )
                    must be sized according to fd_quic_footprint( config )
     config       an instance of fd_quic_config_t to supply configuration parameters

   Returns
     fd_quic_t *  pointer to the new instance */

fd_quic_t *
fd_quic_new( void * mem, fd_quic_config_t const * config ) {
  if( !mem ) return NULL;
  if( !config ) return NULL;

  if( !config->key_file || config->key_file[0] == '\0' ) {
    FD_LOG_ERR(( "fd_quic_new: key_file must be specified" ));
    return NULL;
  }

  if( !config->cert_file || config->cert_file[0] == '\0' ) {
    FD_LOG_ERR(( "fd_quic_new: cert_file must be specified" ));
    return NULL;
  }

  /* TODO open and close key_file and cert_file to ensure read access */

  ulong imem  = (ulong)mem;
  ulong align = fd_quic_align();
  ulong offs  = 0;

  /* check the alignment */
  if( imem % align != 0 ) return NULL;

  fd_quic_t * quic = (fd_quic_t*)(imem + offs);
  if( !quic ) return NULL;

  fd_memset( quic, 0, sizeof( *quic ) );

  offs += FD_QUIC_POW2_ALIGN( sizeof( fd_quic_t ), align );

  // allocate connections
  ulong conn_foot     = fd_quic_conn_footprint( config );
  ulong conn_foot_tot = config->max_concur_conns * conn_foot;

  /* initialize each connection, and add to free list */
  fd_quic_conn_t * last = NULL;
  for( ulong j = 0; j < config->max_concur_conns; ++j ) {
    fd_quic_conn_t * conn = fd_quic_conn_new( (void*)( imem + offs + j * conn_foot ), quic, config );
    conn->next = NULL;
    /* start with minimum supported max datagram */
    /* peers may allow more */
    conn->tx_max_datagram_sz = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;

    if( last == NULL ) {
      quic->conns = conn;
    } else {
      last->next = conn;
    }

    last = conn;
  }

  quic->cur_num_conns = 0;

  offs += FD_QUIC_POW2_ALIGN( conn_foot_tot, align );

  /* make enough space for the hash map slots */
  ulong slot_cnt_bound = config->conn_id_sparsity * config->max_concur_conns * config->max_concur_conn_ids;
  int    lg_slot_cnt    = fd_ulong_find_msb( slot_cnt_bound - 1u ) + 1;

  quic->conn_map = fd_quic_conn_map_new( (void*)( imem + offs), lg_slot_cnt );

  offs += FD_QUIC_POW2_ALIGN( fd_quic_conn_map_footprint( lg_slot_cnt ), align );

  /* make enough space for the events priority queue */
  ulong event_queue_sz = service_queue_footprint( config->max_concur_conns + 1u );

  void * v_service_queue = service_queue_new( (void*)( imem + offs ), config->max_concur_conns + 1u );
  quic->service_queue = service_queue_join( v_service_queue );

  offs += FD_QUIC_POW2_ALIGN( event_queue_sz, align );

  /* configure AIO */
  quic->aio_net_in.cb_receive = fd_quic_aio_cb_receive;
  quic->aio_net_in.context    = (void*)quic;

  quic->aio_net_out           = NULL; // set later

  quic->cert_file             = config->cert_file;
  quic->key_file              = config->key_file;

  quic->transport_params      = *config->transport_params; /* copy transport parameters */
  quic->host_cfg              = config->host_cfg;
  quic->max_concur_conns      = config->max_concur_conns;
  quic->max_concur_streams    = config->max_concur_streams;
  quic->max_concur_handshakes = config->max_concur_handshakes;
  quic->max_in_flight_pkts    = config->max_in_flight_pkts;
  quic->max_in_flight_acks    = config->max_in_flight_acks;
  quic->service_interval      = 1 * (ulong)1e9;

  quic->cb_conn_new           = config->cb_conn_new;
  quic->cb_conn_new           = config->cb_conn_new;

  quic->cb_conn_new           = config->cb_conn_new;
  quic->cb_handshake_complete = config->cb_handshake_complete;
  quic->cb_conn_final         = config->cb_conn_final;
  quic->cb_stream_new         = config->cb_stream_new;
  quic->cb_stream_notify      = config->cb_stream_notify;
  quic->cb_stream_receive     = config->cb_stream_receive;

  /* time function and context */
  quic->now_fn                = config->now_fn;
  quic->now_ctx               = config->now_ctx;

  /* initialize tls */
  fd_quic_tls_cfg_t tls_cfg;
  tls_cfg.cert_file             = config->cert_file;
  tls_cfg.key_file              = config->key_file;
  tls_cfg.max_concur_handshakes = (int)config->max_concur_handshakes;

  /* set up callbacks */
  tls_cfg.client_hello_cb       = fd_quic_tls_cb_client_hello;
  tls_cfg.alert_cb              = fd_quic_tls_cb_alert;
  tls_cfg.secret_cb             = fd_quic_tls_cb_secret;
  tls_cfg.handshake_complete_cb = fd_quic_tls_cb_handshake_complete;

  /* set up alpn */
  tls_cfg.alpns                 = config->alpns;
  tls_cfg.alpns_sz              = config->alpns_sz;

  quic->quic_tls = fd_quic_tls_new( &tls_cfg );

  /* set up networking parameters */
  fd_memcpy( &quic->net, &config->net, sizeof( quic->net ) );

  /* initialize crypto */
  fd_quic_crypto_ctx_init( quic->crypto_ctx );

  return quic;
}


/* fd_quic_delete

   deletes a quic instance and frees all related resources

   Args
     quic         the quic instance to delete */
void
fd_quic_delete( fd_quic_t * quic ) {
  if( !quic ) return;

  fd_quic_conn_map_delete( quic->conn_map );

  service_queue_leave( quic->service_queue );
  service_queue_delete( quic->service_queue );
}


/* connect to remote server

   initiates a new client connection, and returns an object to
   manage it

   the fd_quic_t object owns the returned fd_quic_conn_t
   and manages its lifetime

   args
     dst_ip_addr       destination ip address
     dst_udp_port      destination port number */
fd_quic_conn_t *
fd_quic_connect( fd_quic_t * quic,
                 uint    dst_ip_addr,
                 ushort    dst_udp_port );


/* initiate the clean shutdown of a connection */
void
fd_quic_conn_shutdown( fd_quic_conn_t * conn );


/* initiate a reset of a connection */
void
fd_quic_conn_reset( fd_quic_conn_t * conn );


/* set up quic server parameters and listen for incoming connections

   args
     quic           the quic to configure for listening */
void
fd_quic_listen( fd_quic_t * quic ) {
  quic->listen = 1;
  /* TODO improve this interface
     we have listen() and set_conneciton_cb(), and we don't need two functions */
}


/* start a new stream on a connection

   streams may be unidirectional or bidirectional
   a unidirectional stream passes data from the initiator to its peer

   the user does not own the returned pointer: its lifetime is managed
   by the connection

   args
     conn           the connection from which to derive the stream
     type           one of the following:
                      FD_QUIC_TYPE_UNIDIR - unidirectional stream
                      FD_QUIC_TYPE_BIDIR  - bidirectional stream

   return
     an initialized fd_quic_stream_t   if successful, or
     NULL                              otherwise

*/
fd_quic_stream_t *
fd_quic_conn_new_stream( fd_quic_conn_t * conn, int dirtype ) {
  dirtype &= 1;

  uint server = (uint)conn->server;
  uint type   = server + ( (uint)dirtype << 1u );

  /* have we maxed out our max concurrent streams? */
  ulong max_concur_streams = conn->max_streams[type];
  if( FD_UNLIKELY( ( conn->num_streams[type] == max_concur_streams ) |
                   ( conn->state             != FD_QUIC_CONN_STATE_ACTIVE ) ) ) {
    return NULL;
  }

  /* find unused stream */
  /* linear search since number of allowed concurrent streams expected to
     be low */
  /* could limit this to only locally initiated streams */
  fd_quic_stream_t *  stream          = NULL;
  fd_quic_stream_t ** streams         = conn->streams;
  ulong             tot_num_streams = conn->tot_num_streams;
  for( ulong j = 0; j < tot_num_streams; ++j ) {
    if( streams[j]->stream_id == FD_QUIC_STREAM_ID_UNUSED ) {
      stream = streams[j];
      break;
    }
  }

  /* should not occur
     implies logic error */
  if( FD_UNLIKELY( !stream ) ) {
    FD_LOG_ERR(( "%s : max_concur_streams not reached, yet no free streams found", __func__ ));
  }

  /* generate a new stream id */
  ulong stream_mask    = (ulong)conn->server + ( (ulong)type << (ulong)1 );
  ulong next_stream_id = conn->next_stream_id[stream_mask];
  conn->next_stream_id[stream_mask] = next_stream_id + 4;

  /* stream tx_buf and rx_buf are already set */
  stream->conn      = conn;
  stream->stream_id = next_stream_id;

  /* set the max stream data to the appropriate initial value */
  stream->tx_max_stream_data = ( type == FD_QUIC_TYPE_BIDIR )
                                   ? conn->tx_initial_max_stream_data_bidi_local
                                   : conn->tx_initial_max_stream_data_uni;

  /* probably we should add rx_buf */
  stream->rx_max_stream_data = ( type == FD_QUIC_TYPE_BIDIR )
                                   ? conn->rx_initial_max_stream_data_bidi_local
                                   : 0ul;

  return stream;
}


/* send data

   called to send arbitrary data to a peer
   use fd_quic_conn_new_stream to create a new stream for sending
   or use the new stream callback to obtain a stream for replying

   each buffer in batch must be at most FD_QUIC_MAX_TX_BUF bytes

   sends buffers in order

   args
     stream         the stream to send on
     batch          a pointer to an array of buffers
     batch_sz       the size of the batch

   returns
     TODO replace numeric codes with names
     >=0   number of buffers sent - remaining blocked
      -1   stream id not allowed to send
      -2   connection not in valid state for sending
      -3   blocked from sending - try later */
int
fd_quic_stream_send( fd_quic_stream_t * stream,
                     fd_aio_buffer_t *  batch,
                     ulong              batch_sz ) {
  (void)stream;
  (void)batch;
  (void)batch_sz;

  fd_quic_buffer_t * tx_buf = &stream->tx_buf;

  /* are we allowed to send? */
  ulong stream_id = stream->stream_id;

  /* stream_id & 2 == 0 is bidir
     stream_id & 1 == 0 is client */
  if( FD_UNLIKELY( ( ( (uint)stream_id & 2u ) == 2u ) &
                   ( ( (uint)stream_id & 1u ) == (uint)stream->conn->server ) ) ) {
    return -1;
  }

  fd_quic_conn_t * conn = stream->conn;
  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_ACTIVE ) ) {
    if( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE ||
        conn->state == FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) {
      return 1;
    }
    return -2;
  }

  int buffers_queued = 0;

  /* visit each buffer in batch and store in tx_buf if there is sufficient
     space */
  for( ulong j = 0; j < batch_sz; ++j ) {
    ulong         data_sz = batch[j].data_sz;
    uchar const * data    = batch[j].data;

    if( data_sz > fd_quic_buffer_avail( tx_buf ) ) {
      break;
    }

    /* store data from data into tx_buf
       this stores, but does not move the head offset */
    fd_quic_buffer_store( tx_buf, data, data_sz );

    /* advance head */
    tx_buf->head += data_sz;

    /* account for buffers sent/queued */
    buffers_queued++;
  }

  /* attempt to send */
  fd_quic_conn_tx( stream->conn->quic, stream->conn );

  return buffers_queued;
}


void
fd_quic_stream_close( fd_quic_stream_t * stream, int direction_flags ) {
  (void)stream;
  (void)direction_flags;
}


/* get abstract input/output object

   returns an fd_aio_t object for communicating with the peer
   via the specified stream

   args
     stream         the stream to communicate with

   returns
     an aio object for input and output */
fd_aio_t *
fd_quic_stream_get_aio( fd_quic_stream_t * stream );


/* instantiate these inline functions as visible symbols for completeness */
extern
void
fd_quic_set_cb_stream_receive( fd_quic_t * quic, fd_quic_cb_stream_receive_t cb );

extern
void
fd_quic_set_cb_stream_new( fd_quic_t * quic, fd_quic_cb_stream_new_t cb );

extern
void
fd_quic_set_cb_stream_notify( fd_quic_t * quic, fd_quic_cb_stream_notify_t cb );

extern
fd_aio_t *
fd_quic_get_aio_net_in( fd_quic_t * quic );

extern
void
fd_quic_set_aio_net_out( fd_quic_t * quic, fd_aio_t * aio_out );



/* packet processing */

struct fd_quic_pkt {
  fd_quic_eth_t      eth[1];
  fd_quic_ipv4_t     ipv4[1];
  fd_quic_udp_t      udp[1];

  /* the following are the "current" values only. There may be more QUIC packets
     in a UDP datagram */
  fd_quic_long_hdr_t long_hdr[1];
  ulong              pkt_number;  /* quic packet number currently being decoded/parsed */
  ulong              rcv_time;    /* time packet was received */
  uint               enc_level;   /* encryption level */
  uint               datagram_sz; /* length of the original datagram */
  uint               ack_flag;    /* ORed together: 0-don't ack  1-ack  2-cancel ack */
# define ACK_FLAG_NOT_RQD 0
# define ACK_FLAG_RQD     1
# define ACK_FLAG_CANCEL  2
};


ulong
fd_quic_handle_v1_initial( fd_quic_t *               quic,
                           fd_quic_conn_t *          conn,
                           fd_quic_pkt_t *           pkt,
                           fd_quic_conn_id_t const * conn_id,
                           uchar const *             cur_ptr,
                           ulong                     cur_sz ) {
  uint enc_level = fd_quic_enc_level_initial_id;

  /* according to spec, INITIAL packets less than the specified
     minimum must be discarded, and the connection may be closed
     see rfc9000 14.1 */
  /* TODO reinstate */
  //if( pkt->datagram_sz < FD_QUIC_MIN_INITIAL_PKT_SZ ) {
  //  if( conn ) {
  //    conn->state  = FD_QUIC_CONN_STATE_ABORT;
  //    conn->reason = FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION;

  //    /* TODO reschedule */
  //    return FD_QUIC_PARSE_FAIL;
  //  }
  //}

  /* rfc specifies TLS_AES_128_GCM_SHA256_ID for the suite for initial
     secrets and keys */
  fd_quic_crypto_suite_t * suite = &quic->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];

  /* default orig_conn_id */
  fd_quic_conn_id_t orig_conn_id = *conn_id;

  /* do parse here */
  fd_quic_initial_t initial[1];
  ulong rc = fd_quic_decode_initial( initial, cur_ptr, cur_sz );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) return FD_QUIC_PARSE_FAIL;

  if( FD_UNLIKELY( ( initial->src_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) |
                   ( initial->dst_conn_id_len > FD_QUIC_MAX_CONN_ID_SZ ) ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* if this is a new connection, this will be populated
     in order to remove it in the event of failure */
  fd_quic_conn_entry_t * insert_entry = NULL;

  /* do we have an existing connection? */
  if( !conn ) {

    /* check current number of connections */
    if( quic->cur_num_conns == quic->max_concur_conns ) {
      DEBUG( printf( "fd_quic_handle_v1_initial: new connection would exceed max_concur_conns\n" ); )
      return FD_QUIC_PARSE_FAIL;
    }

    /* fetch top of connection free list */
    conn = quic->conns;
    if( conn == NULL ) { /* no free connections */
      /* TODO send failure back to origin? */

      DEBUG( printf( "fd_quic_handle_v1_initial: no connections in free list\n" ); )
      return FD_QUIC_PARSE_FAIL;
    }

    /* choose new destination connection id */
    fd_quic_conn_id_t new_conn_id = {8u,{0},{0}};

#if 0
    fd_quic_crypto_rand( new_conn_id.conn_id, 8u );
#else
    new_conn_id = *conn_id; /* TEST TODO remove */
#endif

    /* insert into connection map */
    insert_entry = fd_quic_conn_map_insert( quic->conn_map, &new_conn_id );

    /* if insert failed (should be impossible) fail, and do not remove connection
       from free list */
    if( insert_entry == NULL ) {
      return FD_QUIC_PARSE_FAIL;
    }

    /* set connection map insert_entry to new connection */
    insert_entry->conn = conn;

    /* remove from free list */
    quic->conns = conn->next;
    conn->next = NULL;

    /* initialize connection members */
    /* TODO move into separate function */
    conn->quic                 = quic;
    conn->server               = 1;
    conn->version              = pkt->long_hdr->version;
    conn->orig_conn_id.sz      = 0;
    conn->our_conn_id_cnt      = 0;
    conn->peer_cnt             = 0;
    conn->cur_conn_id_idx      = 0;
    conn->cur_peer_idx         = 0;
    /* start with lowest value we allow, then allow peer to increase */
    conn->tx_max_datagram_sz   = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;
    conn->handshake_complete   = 0;
    conn->tls_hs               = NULL; /* created later */

    /* initial max_streams
       we are the server, so start client-initiated at our max-concurrent, and server-initiated at 0
       peer will advertise its configured maximum */
    conn->max_streams[0x00]    = quic->max_concur_streams;   /* 0x00 Client-Initiated, Bidirectional */
    conn->max_streams[0x01]    = 0;                          /* 0x01 Server-Initiated, Bidirectional */
    conn->max_streams[0x02]    = quic->max_concur_streams;   /* 0x02 Client-Initiated, Unidirectional */
    conn->max_streams[0x03]    = 0;                          /* 0x03 Server-Initiated, Unidirectional */


    /* conn->streams initialized inside fd_quic_conn_new */
    /* conn->tot_num_streams initialized inside fd_quic_conn_new */

    /* points to free tx space */
    conn->tx_ptr               = conn->tx_buf;
    conn->tx_sz                = sizeof( conn->tx_buf );

    /* rfc specifies TLS_AES_128_GCM_SHA256_ID for the suite for initial
       secrets and keys */
    conn->suites[enc_level]    = &quic->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];

    /* TODO immediately upon new incoming connection, switch to a newly chosen
       connection id */

    /* rfc9000: s12.3:
       Packet numbers in each packet space start at 0.
       Subsequent packets sent in the same packet number space
         MUST increase the packet number by at least 1
       rfc9002: s3
       It is permitted for some packet numbers to never be used, leaving intentional gaps. */
    fd_memset( conn->exp_pkt_number, 0, sizeof( conn->pkt_number ) );
    fd_memset( conn->pkt_number, 0, sizeof( conn->pkt_number ) );

    /* crypto offset for first packet always starts at 0 */
    fd_memset( conn->tx_crypto_offset, 0, sizeof( conn->pkt_number ) );
    fd_memset( conn->rx_crypto_offset, 0, sizeof( conn->pkt_number ) );

    conn->state                = FD_QUIC_CONN_STATE_HANDSHAKE;
    conn->reason               = 0;
    conn->app_reason           = 0;

    /* insert into service queue */
    fd_quic_event_t event[1] = {{ .timeout = 0, .conn = conn }};
    service_queue_insert( quic->service_queue, event );

  /* if we fail after here, we must remove the connection id from the map
     remove the conn from the service list and return the connection to the free list
     TODO remove from the service list

     TODO actually, set the connection to reset, and clean up resources later */

    /* initialize connection members */
    ulong our_conn_id_idx = conn->our_conn_id_cnt;
    conn->our_conn_id[our_conn_id_idx] = new_conn_id;
    conn->our_conn_id_cnt++;

    /* keep original connection id */
    /* TODO we may not need to keep this indefinitely */
    conn->orig_conn_id = orig_conn_id;

    /* initial source connection id */
    conn->initial_source_conn_id = new_conn_id;

    /* start with minimum supported max datagram */
    /* peers may allow more */
    conn->tx_max_datagram_sz = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;

    ulong peer_idx = conn->peer_cnt;
    fd_memcpy( conn->peer[peer_idx].conn_id.conn_id, initial->src_conn_id, initial->src_conn_id_len );
    conn->peer[peer_idx].conn_id.sz   = initial->src_conn_id_len;
    conn->peer[peer_idx].cur_ip_addr  = pkt->ipv4->saddr;
    conn->peer[peer_idx].cur_udp_port = pkt->udp->srcport;
    conn->peer_cnt++;

    /* adjust transport parameters and encode */

    /* TODO prepare most of the transport parameters, and only append the
       necessary differences */

    /* the original destination connection id
       only sent by server */
    fd_memcpy( quic->transport_params.original_destination_connection_id,
            orig_conn_id.conn_id,
            orig_conn_id.sz );
    quic->transport_params.original_destination_connection_id_present = 1;
    quic->transport_params.original_destination_connection_id_len     = orig_conn_id.sz;

    /* the initial source connection id */
    fd_memcpy( quic->transport_params.initial_source_connection_id,
        conn->initial_source_conn_id.conn_id,
        conn->initial_source_conn_id.sz );
    quic->transport_params.initial_source_connection_id_present = 1;
    quic->transport_params.initial_source_connection_id_len     = conn->initial_source_conn_id.sz;

    /* set the max udp payload size we will accept */
    quic->transport_params.max_udp_payload_size = FD_QUIC_MAX_UDP_PAYLOAD_SZ;

    DEBUG(
    fd_quic_dump_transport_params( &quic->transport_params, stdout );
    fflush( stdout );
    )

    /* flow control params */
    conn->rx_max_data = quic->initial_max_data; /* this is what we advertize initially */
    conn->tx_max_data = 0;                      /* become available at the end of the handshake */
                                                /* TODO they are likely available sooner
                                                   we may want to be able to use them sooner */

    /* no stream bytes sent or received yet */
    conn->tx_tot_data = 0;
    conn->rx_tot_data = 0;

    /* formulate a reply to the request */

    /* encode our transport params to sent to the peer */
    uchar transport_params_raw[FD_QUIC_TRANSPORT_PARAMS_RAW_SZ];
    ulong tp_rc = fd_quic_encode_transport_params( transport_params_raw,
                                                   FD_QUIC_TRANSPORT_PARAMS_RAW_SZ,
                                                   &quic->transport_params );
    /* probably means we don't have enough space for all the transport parameters */
    if( tp_rc == FD_QUIC_ENCODE_FAIL ) {
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }

    ulong transport_params_raw_sz = tp_rc;

    /* create a TLS handshake */
    fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
                                    quic->quic_tls,
                                    (void*)conn,
                                    1 /*is_server*/,
                                    quic->host_cfg.hostname,
                                    transport_params_raw,
                                    transport_params_raw_sz );
    if( !tls_hs ) {
      DEBUG( printf( "fd_quic_handle_v1_initial: fd_quic_tls_hs_new failed\n" ); )
      return FD_QUIC_PARSE_FAIL;
    }
    conn->tls_hs = tls_hs;

    /* generate initial secrets, keys etc */

    /* TODO move this to somewhere more appropriate */
    /* Initial Packets
       from rfc:
       initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
    uchar const * initial_salt    = FD_QUIC_CRYPTO_V1_INITIAL_SALT;
    ulong         initial_salt_sz = FD_QUIC_CRYPTO_V1_INITIAL_SALT_SZ;

    if( fd_quic_gen_initial_secret( &conn->secrets,
                                    initial_salt,         initial_salt_sz,
                                    orig_conn_id.conn_id, conn_id->sz,
                                    suite->hash ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_gen_initial_secret failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }

    if( fd_quic_gen_secrets( &conn->secrets,
                             (int)enc_level, /* generate initial secrets */
                             suite->hash ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_gen_secrets failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }

    /* gen initial keys */
    if( fd_quic_gen_keys( &conn->keys[enc_level][0],
                          (ulong)suite->key_sz,
                          (ulong)suite->iv_sz,
                          suite->hash,
                          conn->secrets.secret[enc_level][0],
                          conn->secrets.secret_sz[enc_level][0] )
          != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_gen_keys failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }

    if( fd_quic_gen_keys( &conn->keys[enc_level][1],
                          (ulong)suite->key_sz,
                          (ulong)suite->iv_sz,
                          suite->hash,
                          conn->secrets.secret[enc_level][1],
                          conn->secrets.secret_sz[enc_level][1] )
          != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_gen_keys failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }
  }

  /* decryption */

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


  /* TODO TESTING - remove */
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

    /* TODO need min packet allowed AND expected packet number */
    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[pn_space] ) ) {
      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;
  } else {
    /* this decrypts the header */
    int server = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt_hdr failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* number of bytes in the packet header */
    pkt_number_sz = ( (uint)dec_hdr[0] & 0x03u ) + 1u;
    tot_sz        = pn_offset + body_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    pkt_number = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );
    DEBUG(
      printf( "pkt_number: %lu\n", (ulong)pkt_number );
      fflush( stdout );
    )

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* TODO need min packet allowed AND expected packet number */
    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[pn_space] ) ) {
      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

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
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt failed\n", __func__ ); )
      if( insert_entry ) {
        fd_quic_conn_map_remove( quic->conn_map, insert_entry );
        conn->next  = quic->conns;
        quic->conns = conn;
      }
      return FD_QUIC_PARSE_FAIL;
    }
  }

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
  while( frame_sz > 0 ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, conn->frame_scratch );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    /* next frame, and remaning size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  DEBUG( printf( "fd_quic_handle_v1_initial: new connection success!\n" ); )

  /* return number of bytes consumed */
  return tot_sz;
}

ulong
fd_quic_handle_v1_handshake(
    fd_quic_t *           quic,
    fd_quic_conn_t *      conn,
    fd_quic_pkt_t *       pkt,
    uchar const *         cur_ptr,
    ulong                cur_sz ) {
  uint enc_level = fd_quic_enc_level_handshake_id;
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;
  DEBUG( printf( "%s START\n", __func__ ); )

  if( !conn ) {
    FD_LOG_WARNING(( "%s called with no connection", __func__ ));
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

  /* connection ids should already be in the relevant structures */

  /* TODO prepare most of the transport parameters, and only append the
     necessary differences */

  /* fetch TLS handshake */
  fd_quic_tls_hs_t * tls_hs = conn->tls_hs;
  if( FD_UNLIKELY( !tls_hs ) ) {
    DEBUG( printf( "fd_quic_handle_v1_handshake: no tls handshake\n" ); )
    return FD_QUIC_PARSE_FAIL;
  }

  /* generate handshake secrets, keys etc */

  /* fetch suite from connection - should be set via callback fd_quic_tls_cb_secret
     from tls */
  fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

  /* check our suite has been chosen */
  if( FD_UNLIKELY( !suite ) ) {
    FD_LOG_WARNING(( "%s : suite missing", __func__ ));
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


  /* TODO TESTING - remove */
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

    /* TODO need min packet allowed AND expected packet number */
    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[pn_space] ) ) {
      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;
  } else {

    /* this decrypts the header */
    int server    = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt_hdr failed\n", __func__ ); )
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
    DEBUG(
      printf( "pkt_number: %lu\n", (ulong)pkt_number );
      fflush( stdout );
    )

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[0] ) ) {
      DEBUG(
          printf( "%s - packet number less than expected. Discarding\n", __func__ );
          fflush( stdout );
          )

      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

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
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt failed\n", __func__ ); )
      return FD_QUIC_PARSE_FAIL;
    }
  }

  /* handle frames */
  ulong        payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = crypt_scratch + payload_off;
  ulong        frame_sz    = body_sz - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz > 0 ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, conn->frame_scratch );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    /* next frame, and remaning size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  /* return number of bytes consumed */
  return tot_sz;
}

ulong
fd_quic_handle_v1_retry( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t const * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;
  DEBUG( printf( "%s STUB\n", __func__ ); )
  return 0;
}

ulong
fd_quic_handle_v1_zero_rtt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t const * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  (void)pkt;
  (void)quic;
  (void)conn;
  (void)cur_ptr;
  (void)cur_sz;
  DEBUG( printf( "%s STUB\n", __func__ ); )
  return 0;
}

ulong
fd_quic_handle_v1_one_rtt( fd_quic_t * quic, fd_quic_conn_t * conn, fd_quic_pkt_t * pkt, uchar const * cur_ptr, ulong cur_sz ) {

  /* encryption level for one_rtt is "appdata" */
  uint enc_level = fd_quic_enc_level_appdata_id;

  /* set on pkt for future processing */
  pkt->enc_level = enc_level;

  fd_quic_one_rtt_t one_rtt[1];

  /* hidden field needed by decode function */
  one_rtt->dst_conn_id_len = 8;

  ulong rc = fd_quic_decode_one_rtt( one_rtt, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    DEBUG( printf( "%s : fd_quic_decode_one_rtt failed\n", __func__ ); )
    return 0;
  }

  DEBUG(
    printf( "%s : dump:\n", __func__ );
    fd_quic_dump_struct_one_rtt( one_rtt );
  )

  /* generate one_rtt secrets, keys etc */

  /* fetch suite from connection - should be set via callback fd_quic_tls_cb_secret
     from tls */
  fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

  /* check our suite has been chosen */
  if( FD_UNLIKELY( !suite ) ) {
    FD_LOG_WARNING(( "%s : suite missing", __func__ ));
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


  /* TODO TESTING - remove */
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

    /* TODO need min packet allowed AND expected packet number */
    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[pn_space] ) ) {
      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

    /* set packet number on the context */
    pkt->pkt_number = pkt_number;

    /* since the packet number is greater than the highest last seen,
       do spin bit processing */
    /* TODO by spec 1 in 16 connections should have this disabled */
    uint spin_bit = (uint)dec_hdr[0] & (1u << 2u);
    conn->spin_bit = (uchar)( spin_bit ^ ( (uint)conn->server ^ 1u ) );

  } else {

    /* this decrypts the header */
    int server = conn->server;

    if( fd_quic_crypto_decrypt_hdr( dec_hdr, &dec_hdr_sz,
                                    cur_ptr, cur_sz,
                                    pn_offset,
                                    suite,
                                    &conn->keys[enc_level][!server] ) != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt_hdr failed\n", __func__ ); )
      return FD_QUIC_PARSE_FAIL;
    }

    /* TODO should we avoid looking at the packet number here
       since the packet integrity is checked in fd_quic_crypto_decrypt? */

    /* number of bytes in the packet header */
    pkt_number_sz = ( (uint)dec_hdr[0] & 0x03u ) + 1u;
    tot_sz        = cur_sz; /* total including header and payload */

    /* now we have decrypted packet number */
    /* TODO packet number processing */
    pkt_number = fd_quic_parse_bits( dec_hdr + pn_offset, 0, 8u * pkt_number_sz );
    DEBUG(
      printf( "pkt_number: %lu\n", (ulong)pkt_number );
      fflush( stdout );
    )

    /* packet number space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* reconstruct packet number */
    fd_quic_reconstruct_pkt_num( &pkt_number, pkt_number_sz, conn->exp_pkt_number[pn_space] );

    /* packet number must be greater than the last processed
       on a new connection, the minimum allowed is set to zero */
    if( FD_UNLIKELY( pkt_number < conn->exp_pkt_number[0] ) ) {
      DEBUG(
          printf( "%s - packet number less than expected. Discarding\n", __func__ );
          fflush( stdout );
          )

      /* packet already processed or abandoned, simply discard */
      return tot_sz; /* return bytes to allow for more packets to be processed */
    }

    /* since the packet number is greater than the highest last seen,
       do spin bit processing */
    /* TODO by spec 1 in 16 connections should have this disabled */
    uint spin_bit = (uint)dec_hdr[0] & (1u << 2u);
    conn->spin_bit = (uchar)( spin_bit ^ ( (uint)conn->server ^ 1u ) );

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
      DEBUG( fprintf( stderr, "%s: fd_quic_crypto_decrypt failed\n", __func__ ); )
      return FD_QUIC_PARSE_FAIL;
    }
  }

  /* handle frames */
  ulong         payload_off = pn_offset + pkt_number_sz;
  uchar const * frame_ptr   = crypt_scratch + payload_off;
  ulong         frame_sz    = cur_sz - pn_offset - pkt_number_sz - FD_QUIC_CRYPTO_TAG_SZ; /* total size of all frames in packet */
  while( frame_sz > 0 ) {
    rc = fd_quic_handle_v1_frame( quic, conn, pkt, frame_ptr, frame_sz, conn->frame_scratch );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    /* next frame, and remaning size */
    frame_ptr += rc;
    frame_sz  -= rc;
  }

  //fd_quic_handle_frames( quic, conn, pkt, cur_ptr, cur_sz );
  return 0;
}


void
fd_quic_reschedule_conn( fd_quic_conn_t * conn, ulong timeout ) {
  fd_quic_t * quic = conn->quic;

  /* set new timeout */
  /* only brings it in - never pushed it out */
  if( timeout < conn->next_service_time ) {
    /* find conn in events, then remove, update, insert */
    fd_quic_event_t * event     = NULL;
    ulong            event_idx = 0;
    ulong            cnt   = service_queue_cnt( quic->service_queue );
    for( ulong j = 0; j < cnt; ++j ) {
      fd_quic_event_t * cur_event = quic->service_queue + j;
      if( cur_event->conn == conn ) {
        event     = cur_event;
        event_idx = j;
        break;
      }
    }

    /* this shouldn't happen, unless the connection is dead */
    if( FD_UNLIKELY( !event ) ) {
      /* TODO could do a sanity check here that the state is a dead one */
      return;
    }

    /* copy event before removing it */
    fd_quic_event_t lcl_event = *event;

    /* remove */
    service_queue_remove( quic->service_queue, event_idx );

    /* update */
    lcl_event.timeout = timeout;

    /* insert */
    service_queue_insert( quic->service_queue, &lcl_event );

    conn->next_service_time = timeout;
  }
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
  ulong now           = quic->now_fn( quic->now_ctx );
  ulong ack_time      = now + 1;                 /* initial and handshake ack-eliciting packets
                                                  should ack immediately */
  uint ack_mandatory = pkt->ack_flag & ACK_FLAG_RQD;

  /* packet contains ack-eliciting frame */
  if( ack_mandatory ) {
    pkt->ack_flag = 0;
    if( enc_level != fd_quic_enc_level_initial_id &&
        enc_level != fd_quic_enc_level_handshake_id ) {
      ack_time = now + conn->peer_max_ack_delay; /* TODO subtract rtt? */
    }
  } else {
    /* not ack-eliciting */
    /* if it's been too long, we can send a ping */
    ack_time = now + quic->service_interval; /* randomize */
  }

  //DEBUG( return; )

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
         insert at head
           so the acks are in descending order of packet number */
  ulong pkt_number = pkt->pkt_number;
  (void)pkt_number;

  fd_quic_ack_t ** acks_free   = &conn->acks_free;
  fd_quic_ack_t ** acks_tx     = conn->acks_tx     + enc_level;
  fd_quic_ack_t ** acks_tx_end = conn->acks_tx_end + enc_level;

  /* if there exists a last unsent ack, and it refers to the prior packet,
     extend it
     range.offset_hi refers the the last offset + 1 */
  if( pkt_number > 0u && *acks_tx && (*acks_tx)->pkt_number.offset_hi == pkt_number &&
      ( (*acks_tx)->flags & FD_QUIC_ACK_FLAGS_SENT ) == 0u ) {
    (*acks_tx)->pkt_number.offset_hi++;

    /* if the calculaed ack time is sooner than this ack, update
       and reschedule service */
    if( ack_time < (*acks_tx)->tx_time ) {
      (*acks_tx)->tx_time = ack_time;
      fd_quic_reschedule_conn( conn, ack_time );
    }
  }

  /* we need to allocate an ack */
  fd_quic_ack_t * ack = *acks_free;

  if( FD_UNLIKELY( !ack ) ) {
    /* no ack - free an old one */
    /* TODO, when we discard an ack, we must increase a "min_accept_pkt_number" for that pn_space */

    /* iterate thru used acks until end, so we know prior */
    fd_quic_ack_t * cur_ack     = conn->acks_tx    [enc_level];
    fd_quic_ack_t * last_ack    = conn->acks_tx_end[enc_level];
    fd_quic_ack_t * prior_ack   = NULL;
    while( cur_ack && cur_ack != last_ack ) {
      prior_ack  = cur_ack;
      cur_ack    = cur_ack->next;
    }

    if( FD_UNLIKELY( !cur_ack ) ) {
      /* this shouldn't be possible */
      return;
    }

    /* we should always have a prior */
    if( FD_LIKELY( prior_ack ) ) {
      /* remove from used list */
      prior_ack->next = NULL;
    } else {
      /* this could occur if only 1 ack is allocated
         -- don't do that */
      /* remove from head */
      conn->acks_tx[enc_level] = NULL;
    }

    /* use removed */
    ack = cur_ack;
  }

  /* move head of free list to next ack */
  *acks_free = ack->next;

  /* we have an ack, populate and insert at head of appropriate list */
  ack->tx_pkt_number        = FD_QUIC_PKT_NUM_UNUSED; /* unset */
  ack->pkt_number.offset_lo = pkt_number;
  ack->pkt_number.offset_hi = pkt_number + 1u;    /* offset_hi is the next one */
  ack->next                 = *acks_tx;           /* points to head of list for current enc_level */
  ack->enc_level            = (uchar)enc_level; /* don't really need - it's implied */
  ack->pn_space             = (uchar)pn_space;  /* don't really need - it's implied */
  ack->flags                = ack_mandatory ? FD_QUIC_ACK_FLAGS_MANDATORY : 0u;
  ack->tx_time              = ack_time;
  ack->pkt_rcvd             = pkt->rcv_time;      /* the time the packet was received */

  /* insert at front of list */
  if( *acks_tx_end == NULL ) *acks_tx_end = ack;
  *acks_tx = ack;

  fd_quic_reschedule_conn( conn, ack_time );

}

/* process v1 quic packets
   only called for packets with long header
   returns number of bytes consumed, or FD_QUIC_PARSE_FAIL upon error
   assumes cur_sz >= FD_QUIC_SHORTEST_PKT */
#define FD_QUIC_SHORTEST_PKT 16
ulong
fd_quic_process_quic_packet_v1( fd_quic_t * quic, fd_quic_pkt_t * pkt, uchar const * cur_ptr, ulong cur_sz ) {
  fd_quic_conn_entry_t * entry = NULL;
  fd_quic_conn_t *       conn  = NULL;

  if( FD_UNLIKELY( cur_sz < FD_QUIC_SHORTEST_PKT ) ) return FD_QUIC_PARSE_FAIL;

  /* keep end */
  uchar const * orig_ptr = cur_ptr;

  /* extract the dst connection id */
  fd_quic_conn_id_t dst_conn_id = { FD_QUIC_CONN_ID_SZ, {0}, {0} }; /* initialize assumeing fixed-length conn id */

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
    entry = fd_quic_conn_map_query( quic->conn_map, &dst_conn_id );
    conn  = entry ? entry->conn : NULL;

    /* encryption level matches that of TLS */
    pkt->enc_level = common_hdr->long_packet_type; /* V2 uses an indirect mapping */

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* long_packet_type is 2 bits, so only four possibilities */
    switch( common_hdr->long_packet_type ) {
      case FD_QUIC_PKTTYPE_V1_INITIAL:
        rc = fd_quic_handle_v1_initial( quic, conn, pkt, &dst_conn_id, cur_ptr, cur_sz );
        entry = fd_quic_conn_map_query( quic->conn_map, &dst_conn_id );
        conn  = entry ? entry->conn : NULL; /* TODO is this the correct dst_conn_is to look up? */
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
    } else {
      __asm__( "nop" ); /* TODO remove */
    }

  } else { /* short header */
    /* caller checks cur_sz is sufficient */
    fd_memcpy( &dst_conn_id.conn_id, cur_ptr+1, FD_QUIC_CONN_ID_SZ );

    /* encryption level of short header packets is fd_quic_enc_level_appdata_id */
    pkt->enc_level = fd_quic_enc_level_appdata_id;

    /* initialize packet number to unused value */
    pkt->pkt_number = FD_QUIC_PKT_NUM_UNUSED;

    /* find connection id */
    entry = fd_quic_conn_map_query( quic->conn_map, &dst_conn_id );
    if( !entry ) {
      DEBUG( printf( "%s : one_rtt failed: no connection found\n", __func__ ); )
      return FD_QUIC_PARSE_FAIL;
    }

    conn = entry->conn;

    rc = fd_quic_handle_v1_one_rtt( quic, conn, pkt, cur_ptr, cur_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;
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
fd_quic_process_packet( fd_quic_t * quic, uchar const * data, ulong data_sz ) {
  ulong rc = 0;

  /* holds the remainder of the packet*/
  uchar const * cur_ptr = data;
  ulong        cur_sz  = data_sz;

  if( data_sz > 0xffffu ) {
    /* sanity check */
    FD_LOG_WARNING(( "%s - unreasonably large packet received (%lu). Discarding",
          __func__, (ulong)data_sz ));
    return;
  }

  fd_quic_pkt_t pkt = { .datagram_sz = (uint)data_sz };

  pkt.rcv_time = quic->now_fn( quic->now_ctx );

  /* parse eth, ip, udp */
  rc = fd_quic_decode_eth( pkt.eth, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    /* TODO count failure, log-debug failure */
    return;
  }

  /* TODO support for vlan? */

  if( pkt.eth->eth_type != 0x0800 ) {
    DEBUG( printf( "Invalid ethertype: %4.4x\n", pkt.eth->eth_type ); )
    return;
  }

  /* update pointer + size */
  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_decode_ipv4( pkt.ipv4, cur_ptr, cur_sz );
  if( rc == FD_QUIC_PARSE_FAIL ) {
    /* TODO count failure, log-debug failure */
    return;
  }

  /* check version, tot_len, protocol, checksum? */
  if( ( pkt.ipv4->version != 4 ) | ( pkt.ipv4->protocol != 17 ) ) {
    DEBUG( printf( "failed: version=%u protocol=%u\n", pkt.ipv4->version, pkt.ipv4->protocol ); )
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

  /* debugging */
  DEBUG(
      printf( "fd_quic_process_packet: received packet with headers:\n" );
      fd_quic_dump_struct_eth( pkt.eth );
      fd_quic_dump_struct_ipv4( pkt.ipv4 );
      fd_quic_dump_struct_udp( pkt.udp );
      printf( "\n" ); )
  /* end debugging */

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
  if( cur_sz < FD_QUIC_SHORTEST_PKT ) return;

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
       /* TODO implement version negoatiation */
      return;
    }

    if( version != 1 ) {
      /* cannot interpret length, so discard entire packet */
      /* TODO send version negotiation */
      return;
    }

    /* 0x?a?a?a?au is intended to force version negotation
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

      if( cur_version != version ) {
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

      if( rc == FD_QUIC_PARSE_FAIL ) {
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
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &dst_conn_id );
    if( !entry ) {
      DEBUG( printf( "%s : one_rtt failed: no connection found\n", __func__ ); )
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
ulong
fd_quic_aio_cb_receive( void *            context,
                        fd_aio_buffer_t * batch,
                        ulong            batch_sz ) {
  fd_quic_t * quic = (fd_quic_t*)context;

  /* preliminary parse */
  /* this aio interface is configured as one-packet per buffer
     so batch[0] refers to one buffer
     as such, we simply forward each individual packet to a handling function */
  for( ulong j = 0; j < batch_sz; ++j ) {
    fd_quic_process_packet( quic, batch[j].data, batch[j].data_sz );
  }

  /* the assumption here at present is that any packet that could not be processed
     is simply dropped
     hence, all packets were consumed */
  return batch_sz;
}

/* define callbacks from quic-tls into quic */
int
fd_quic_tls_cb_client_hello( fd_quic_tls_hs_t * hs,
                             void *             context ) {
  (void)hs;
  (void)context;
  DEBUG( printf( "TLS CALLBACK: %s\n", __func__ ); )
  return FD_QUIC_TLS_SUCCESS; /* accept everything */
}

void
fd_quic_tls_cb_alert( fd_quic_tls_hs_t * hs,
                      void *             context,
                      int                alert ) {
  (void)hs;
  (void)context;
  (void)alert;
  DEBUG( fd_quic_conn_t * conn = (fd_quic_conn_t*)context;
         printf( "TLS : %s\n", conn->server ? "SERVER" : "CLIENT"  );
         printf( "TLS alert: %d\n", alert );
         printf( "TLS CALLBACK: %s\n", __func__ );
         printf( "TLS alert: %s %s\n",
                   SSL_alert_type_string_long( alert ),
                   SSL_alert_desc_string_long( alert ) ); )

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
  DEBUG( printf( "TLS CALLBACK: %s\n", __func__ ); )

  fd_quic_conn_t * conn   = (fd_quic_conn_t*)context;
  int              server = conn->server;
  DEBUG( printf( "TLS %s\n", server ? "server" : "client" ); )

  /* look up suite */
  /* set secrets */
  if( FD_UNLIKELY( secret->enc_level < 0 || secret->enc_level >= FD_QUIC_NUM_ENC_LEVELS ) ) {
    FD_LOG_WARNING(( "%s : callback with invalid encryption level", __func__ ));
    return;
  }

  if( FD_UNLIKELY( secret->secret_len > FD_QUIC_MAX_SECRET_SZ ) ) {
    FD_LOG_WARNING(( "%s : callback with invalid secret length", __func__ ));
    return;
  }

  uint enc_level = secret->enc_level;

  fd_quic_crypto_secrets_t * crypto_secret = &conn->secrets;

  uchar secret_sz = (uchar)secret->secret_len;
  crypto_secret->secret_sz[enc_level][0] = secret_sz;
  crypto_secret->secret_sz[enc_level][1] = secret_sz;

  DEBUG(
      printf( "%s read  secret - enc_level: %d  secret: ", conn->server ? "SERVER" : "CLIENT", enc_level );
      for( ulong j = 0; j < secret_sz; ++j ) {
        printf( "%2.2x", (uint)secret->read_secret[j] );
      }
      printf( "\n" );
      printf( "%s write secret - enc_level: %d  secret: ", conn->server ? "SERVER" : "CLIENT", enc_level );
      for( ulong j = 0; j < secret_sz; ++j ) {
        printf( "%2.2x", (uint)secret->write_secret[j] );
      }
      printf( "\n" );
    )

  fd_memcpy( &crypto_secret->secret[enc_level][!server][0], secret->read_secret,  secret_sz );
  fd_memcpy( &crypto_secret->secret[enc_level][ server][0], secret->write_secret, secret_sz );

  uint suite_id = secret->suite_id;
  uchar major = (uchar)( suite_id >> 8u );
  uchar minor = (uchar)( suite_id );
  int suite_idx = fd_quic_crypto_lookup_suite( major, minor );

  DEBUG(
      printf( "suite: majmin: %u %u  suite_id: %x  suite_idx: %u\n",
        (uint)major, (uint)minor, (uint)suite_id, (uint)suite_idx );
      )

  if( suite_idx >= 0 ) {
    fd_quic_crypto_suite_t * suite = conn->suites[enc_level] = &conn->quic->crypto_ctx->suites[suite_idx];

    /* gen keys */
    if( fd_quic_gen_keys( &conn->keys[enc_level][0],
                          (ulong)suite->key_sz,
                          (ulong)suite->iv_sz,
                          suite->hash,
                          conn->secrets.secret[enc_level][0],
                          conn->secrets.secret_sz[enc_level][0] )
          != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_LOG_WARNING(( "%s: fd_quic_gen_keys failed on client\n", __func__ ));
    }

    /* gen initial keys */
    if( fd_quic_gen_keys( &conn->keys[enc_level][1],
                          (ulong)suite->key_sz,
                          (ulong)suite->iv_sz,
                          suite->hash,
                          conn->secrets.secret[enc_level][1],
                          conn->secrets.secret_sz[enc_level][1] )
          != FD_QUIC_SUCCESS ) {
      /* remove connection from map, and insert into free list */
      FD_LOG_WARNING(( "%s: fd_quic_gen_keys failed on server\n", __func__ ));
    }

  }

}

void
fd_quic_tls_cb_handshake_complete( fd_quic_tls_hs_t * hs,
                                   void *             context  ) {
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

        fd_quic_transport_params_t * our_tp = &conn->peer_transport_params;
        conn->rx_max_data                            = our_tp->initial_max_data;
        conn->rx_initial_max_stream_data_uni         = our_tp->initial_max_stream_data_uni;
        conn->rx_initial_max_stream_data_bidi_local  = our_tp->initial_max_stream_data_bidi_local;
        conn->rx_initial_max_stream_data_bidi_remote = our_tp->initial_max_stream_data_bidi_remote;

        /* max datagram size */
        ulong tx_max_datagram_sz = peer_tp->max_udp_payload_size;
        if( tx_max_datagram_sz < FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ ) {
          tx_max_datagram_sz = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;
        }
        if( tx_max_datagram_sz > FD_QUIC_MAX_UDP_PAYLOAD_SZ ) {
          tx_max_datagram_sz = FD_QUIC_MAX_UDP_PAYLOAD_SZ;
        }
        conn->tx_max_datagram_sz = (uint)tx_max_datagram_sz;

        /* max streams
           set the initial max allowed by the peer */
        if( conn->server ) {
          /* 0x01 server-initiated, bidirectional */
          conn->max_streams[0x01] = (uint)peer_tp->initial_max_streams_bidi;
          /* 0x03 server-initiated, unidirectional */
          conn->max_streams[0x03] = (uint)peer_tp->initial_max_streams_uni;
        } else {
          /* 0x00 client-initiated, bidirectional */
          conn->max_streams[0x00] = (uint)peer_tp->initial_max_streams_bidi;
          /* 0x02 client-initiated, unidirectional */
          conn->max_streams[0x02] = (uint)peer_tp->initial_max_streams_uni;
        }

        return;
      }

    default:
      FD_LOG_WARNING(( "%s : handshake in unexpected state: %u", __func__, (uint)conn->state ));
  }
}

static ulong
fd_quic_frame_handle_crypto_frame( void *                   vp_context,
                                   fd_quic_crypto_frame_t * crypto,
                                   uchar const *            p,
                                   ulong                   p_sz ) {
  /* copy the context locally */
  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  DEBUG(
    printf( "CRYPTO\n" );
    fd_quic_dump_struct_crypto_frame( crypto );

    printf( "enc_level: %d\n", (int)context.pkt->enc_level );
    )

  DEBUG(
      printf( "%s : %s calling fd_quic_tls_provide_data with %ld bytes, enc_level: %d\n",
        __func__,
        ( context.conn->server ? "SERVER" : "CLIENT" ),
        (long)crypto->length,
        (int)context.pkt->enc_level );
      for( ulong j = 0; j < crypto->length; ++j ) {
        printf( "%2.2x ", crypto->crypto_data[j] );
      }
      printf( "\n" );
    )

  /* determine whether any of the data was already provided */
  fd_quic_conn_t * conn      = context.conn;
  uint         enc_level = context.pkt->enc_level;

  /* offset expected */
  ulong           exp_offset = conn->rx_crypto_offset[enc_level];
  ulong           rcv_offset = crypto->offset;
  ulong           rcv_sz     = crypto->length;

  /* do we have bytes we can use? */
  if( FD_LIKELY( rcv_offset <= exp_offset && rcv_offset + rcv_sz > exp_offset ) ) {
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
      DEBUG(
        fprintf( stderr, "fd_quic_tls_process error at: %s %s %d\n", __func__, __FILE__, __LINE__ );
      )
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
  ulong now = quic->now_fn( quic->now_ctx );

  /* service events */
  while( service_queue_cnt( quic->service_queue ) ) {
    fd_quic_event_t * event = &quic->service_queue[0];

    ulong service_time = event->timeout;
    if( now < service_time ) break;

    fd_quic_conn_t * conn = event->conn;
    fd_quic_conn_service( quic, conn, now );

    if( conn->next_service_time <= now ) {
      conn->next_service_time = now + quic->service_interval;
    }

    /* remove event, and reinsert at new time */
    service_queue_remove_min( quic->service_queue );

    /* dead? don't reinsert, just clean up */
    if( conn->state == FD_QUIC_CONN_STATE_DEAD ) {
      /* inform user before freeing */
      if( FD_LIKELY( quic->cb_conn_final ) ) {
        quic->cb_conn_final( conn, quic->context );
      }

      fd_quic_conn_free( quic, conn );
    } else {
      event->timeout = conn->next_service_time;
      service_queue_insert( quic->service_queue, event );
    }
  }
}


/* attempt transmit buffered data

   prior to call, conn->tx_ptr points to the first free byte in conn->tx_buf
   the data in tx_buf..tx_ptr is prepended by networking headers
   and put on the wire

   returns 0 if successful, or 1 otherwise */
uint
fd_quic_tx_buffered( fd_quic_t * quic, fd_quic_conn_t * conn ) {
  /* TODO leave space at front of tx_buf for header
     then encode directly into it to avoid 1 copy */
  long payload_sz = conn->tx_ptr - conn->tx_buf;

  /* nothing to do */
  if( payload_sz <= 0 ) return 0;

  DEBUG(
      {
        printf( "fd_quic_tx_buffered:\n" );
        uchar const * end_ptr = conn->tx_ptr;
        uchar const * cur_ptr = conn->tx_buf;
        while( cur_ptr < end_ptr ) {
          printf( "%2.2x ", (uint)*cur_ptr );
          cur_ptr++;
        }
        printf( "\n" );
        fflush( stdout );
      }
    )

  ulong                  peer_idx   = conn->cur_peer_idx;
  fd_quic_endpoint_t *   peer       = &conn->peer[peer_idx];
  fd_quic_host_cfg_t *   host_cfg   = &quic->host_cfg; /* TODO put on conn
                                                          outgoing connections will need to choose a udp src port */

  uchar * cur_ptr = conn->crypt_scratch;
  ulong  cur_sz  = sizeof( conn->crypt_scratch );

  /* TODO much of this may be prepared ahead of time */
  fd_quic_pkt_t pkt;

  fd_memcpy( pkt.eth->dst_addr, quic->net.default_route_mac, sizeof( pkt.eth->dst_addr ) );
  fd_memcpy( pkt.eth->src_addr, quic->net.src_mac,           sizeof( pkt.eth->src_addr ) );
  pkt.eth->eth_type = 0x0800;

  pkt.ipv4->version  = 4;
  pkt.ipv4->ihl      = 5;
  pkt.ipv4->dscp     = quic->dscp; /* could make this per-connection or per-stream */
  pkt.ipv4->ecn      = 0;          /* explicit congestion notification */
  pkt.ipv4->tot_len  = (ushort)( 20 + 8 + payload_sz );
  pkt.ipv4->id       = conn->ipv4_id++;
  pkt.ipv4->frag_off = 0x4000u; /* don't fragment */
  pkt.ipv4->ttl      = 64; /* TODO make configurable */
  pkt.ipv4->protocol = 17; /* UDP */
  pkt.ipv4->check    = 0;
  pkt.ipv4->saddr    = host_cfg->ip_addr;
  pkt.ipv4->daddr    = peer->cur_ip_addr;

  pkt.udp->srcport   = host_cfg->udp_port;
  pkt.udp->dstport   = peer->cur_udp_port;
  pkt.udp->length    = (ushort)( 8 + payload_sz );
  pkt.udp->check     = 0x0000;

  /* TODO improve on this */
  fd_memset( cur_ptr, -1, 14 + 20 + 8 );

  ulong rc = fd_quic_encode_eth( cur_ptr, cur_sz, pkt.eth );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "%s : fd_quic_encode_eth failed with buffer overrun", __func__ ));
  }

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_encode_ipv4( cur_ptr, cur_sz, pkt.ipv4 );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "%s : fd_quic_encode_ipv4 failed with buffer overrun", __func__ ));
  }

  /* calc checksum */
  fd_quic_net_ipv4_checksum( cur_ptr );

  cur_ptr += rc;
  cur_sz  -= rc;

  rc = fd_quic_encode_udp( cur_ptr, cur_sz, pkt.udp );
  if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_LOG_ERR(( "%s : fd_quic_encode_udp failed with buffer overrun", __func__ ));
  }

  cur_ptr += rc;
  cur_sz  -= rc;

  /* need enough space for payload and tag */
  ulong tag_sz = FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( (ulong)payload_sz + tag_sz > cur_sz ) ) {
    FD_LOG_WARNING(( "%s : payload too big for buffer", __func__ ));

    /* reset buffer, since we can't use its contents */
    conn->tx_ptr = conn->tx_buf;
    conn->tx_sz  = sizeof( conn->tx_buf );
    return 1;
  }
  fd_memcpy( cur_ptr, conn->tx_buf, (ulong)payload_sz );

  cur_ptr += (ulong)payload_sz;
  cur_sz  -= (ulong)payload_sz;

  fd_aio_buffer_t aio_buf = { conn->crypt_scratch, .data_sz = (ulong)( cur_ptr - conn->crypt_scratch ) };
  ulong aio_rc = fd_aio_send( quic->aio_net_out, &aio_buf, 1 );
  if( ~aio_rc == 0u ) {
    FD_LOG_WARNING(( "Fatal error reported by aio peer" ));
    /* drop thru to reset buffer */
  } else if( aio_rc == 0 ) {
    /* transient condition - try later */
    return 1;
  }

  /* after send, reset tx_ptr and tx_sz */
  conn->tx_ptr = conn->tx_buf;
  conn->tx_sz  = sizeof( conn->tx_buf );

  return 0; /* success */
}


struct fd_quic_pkt_hdr {
  union {
    fd_quic_initial_t   initial;
    fd_quic_handshake_t handshake;
    fd_quic_one_rtt_t   one_rtt;
    /* don't currently support early data */
  } quic_pkt;
  uint enc_level; /* implies the type of quic_pkt */
};
typedef struct fd_quic_pkt_hdr fd_quic_pkt_hdr_t;


/* populate the fd_quic_pkt_hdr_t */
void
fd_quic_pkt_hdr_populate( fd_quic_pkt_hdr_t * pkt_hdr,
                          uint            enc_level,
                          ulong            pkt_number,
                          fd_quic_conn_t *    conn ) {
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

      /* destination */
      fd_memcpy( pkt_hdr->quic_pkt.initial.dst_conn_id,
              peer_conn_id->conn_id,
              peer_conn_id->sz );
      pkt_hdr->quic_pkt.initial.dst_conn_id_len = peer_conn_id->sz;

      /* source */
      fd_memcpy( pkt_hdr->quic_pkt.initial.src_conn_id,
              conn_id->conn_id,
              conn_id->sz );
      pkt_hdr->quic_pkt.initial.src_conn_id_len = conn_id->sz;

      pkt_hdr->quic_pkt.initial.token_len       = 0; /* not supported */

      pkt_hdr->quic_pkt.initial.len             = 0; /* length of payload initially 0 */
      pkt_hdr->quic_pkt.initial.pkt_num         = pkt_number;
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
      fd_memcpy( pkt_hdr->quic_pkt.handshake.dst_conn_id,
              peer_conn_id->conn_id,
              peer_conn_id->sz );
      pkt_hdr->quic_pkt.handshake.dst_conn_id_len = peer_conn_id->sz;

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
      pkt_hdr->quic_pkt.one_rtt.spin_bit         = sb;     /* should either match or flip for client/server */
                                                           /* randomized for disabled spin bit */
      pkt_hdr->quic_pkt.one_rtt.reserved0        = 0;      /* must be set to zero by rfc9000 17.2 */
      pkt_hdr->quic_pkt.one_rtt.key_phase        = 0;      /* flipped on key change */
      pkt_hdr->quic_pkt.one_rtt.pkt_number_len   = 3;      /* indicates 4-byte packet number TODO vary? */
      pkt_hdr->quic_pkt.one_rtt.pkt_num_bits     = 4 * 8;  /* actual number of bits to encode */

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
    case fd_quic_enc_level_initial_id:
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

  /* record the metadata for items stored in the packet */
  fd_quic_pkt_meta_t pkt_meta = {0};

  fd_quic_pkt_hdr_t pkt_hdr;

  /* temporary usage
     data is populated, then encoded into a buffer
     so only one member in use */
  union {
    fd_quic_crypto_frame_t     crypto;
    fd_quic_ack_frame_t        ack;
    fd_quic_stream_frame_t     stream;
    fd_quic_max_stream_data_t  max_stream_data;
    fd_quic_max_data_frame_t   max_data;
    fd_quic_conn_close_frame_t conn_close;
  } frame;

  while(1) {
    ulong              frame_sz     = 0;
    ulong              tot_frame_sz = 0;
    ulong              data_sz      = 0;
    uchar const *      data         = NULL;
    fd_quic_stream_t * stream       = NULL;
    uint               initial_pkt  = 0;    /* is this the first initial packet? */

    /* do we have space for pkt_meta? */
    fd_quic_pkt_meta_t * pm_new = conn->pkt_meta_free;
    if( FD_UNLIKELY( !pm_new ) ) {
      DEBUG(
          printf( "%s - packet metadata free list is empty\n", __func__ );
          )
      return;
    }

    /* choose enc_level to tx at */
    uint enc_level = fd_quic_tx_enc_level( conn );

    /* nothing to send? */
    if( enc_level == ~0u ) break;

    uint closing    = 0; /* are we closing? */
    uint peer_close = 0; /* did peer request close? */

    /* check status */
    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_DEAD:
        /* do not send on dead connection at all */
        return;

      case FD_QUIC_CONN_STATE_PEER_CLOSE:
        peer_close = 1u;
        /* fall thru */

      case FD_QUIC_CONN_STATE_ABORT:
      case FD_QUIC_CONN_STATE_CLOSE_PENDING:
        closing = 1u;
    }

    /* encode into here */
    uchar * cur_ptr = crypt_scratch;
    ulong   cur_sz  = crypt_scratch_sz;

    /* TODO determine actual datagrams size to use */
    if( cur_sz > tx_max_datagram_sz ) cur_sz = tx_max_datagram_sz;

    /* determine pn_space */
    uint pn_space = fd_quic_enc_level_to_pn_space( enc_level );

    /* get next packet number
       we burn this number immediately - quic allows gaps, so this isn't harmful
       even if we end up not sending */
    ulong pkt_number = conn->pkt_number[pn_space]++;

    /* this is the start of a new quic packet
       cur_ptr points at the next byte to fill with a quic pkt */
    /* currently, cur_ptr just points at the start of crypt_scratch
       each quic packet gets encrypted into tx_buf, and the space in
       crypt_scratch is reused */

    /* populate the quic packet header */
    fd_quic_pkt_hdr_populate( &pkt_hdr, enc_level, pkt_number, conn );

    ulong initial_hdr_sz = fd_quic_pkt_hdr_footprint( &pkt_hdr, enc_level );

    /* if we don't have space for an initial header plus
       16 for sample, 16 for tag and 3 bytes for expansion,
       try tx to free space */
    if( initial_hdr_sz + 35 > cur_sz ) {
      uint rc = fd_quic_tx_buffered( quic, conn );
      if( rc != 0u ) {
        /* unable to free space, or should reschedule for another reason */
        ulong now = quic->now_fn( quic->now_ctx );
        fd_quic_reschedule_conn( conn, now + 1000000u );
      }
      return;
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
    fd_quic_ack_t * cur_ack_head = conn->acks_tx[enc_level];
    if( cur_ack_head && !( cur_ack_head->flags & FD_QUIC_ACK_FLAGS_SENT ) ) {
      ack_head = cur_ack_head;
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

      /* put ack frame */
      frame.ack.type            = 0x02u; /* type 0x02 is the base ack, 0x03 indicates ECN */
      frame.ack.largest_ack     = ack_head->pkt_number.offset_hi - 1u;
      frame.ack.ack_delay       = quic->now_fn( quic->now_ctx ) - ack_head->pkt_rcvd;
      frame.ack.ack_range_count = 0; /* no fragments */
      frame.ack.first_ack_range = ack_head->pkt_number.offset_hi - ack_head->pkt_number.offset_lo - 1u;

      /* calc size of ack frame */
      frame_sz  = fd_quic_encode_footprint_ack_frame( &frame.ack );

      if( payload_ptr + frame_sz < payload_end ) {
        frame_sz = fd_quic_encode_ack_frame( payload_ptr,
                                             (ulong)( payload_end - payload_ptr ),
                                             &frame.ack );
        if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
          /* shouldn't happend */
          FD_LOG_WARNING(( "%s - failed to encode ack", __func__ ));
        } else {
          payload_ptr  += frame_sz;
          tot_frame_sz += frame_sz;

          /* must add acks to packet metadata */
          ack_head->tx_pkt_number = pkt_number;
          pkt_meta.flags         |= FD_QUIC_PKT_META_FLAGS_ACK;
        }
      }
    }

    /* closing? */
    if( FD_UNLIKELY( closing ) ) {
      if( !peer_close && !( conn->flags & FD_QUIC_CONN_FLAGS_CLOSE_SENT ) ) {
        /* only send one unless timeout before ack */
        conn->flags |= FD_QUIC_CONN_FLAGS_CLOSE_SENT;

        /* we ack the close */
        if( conn->reason != 0u ) {
          frame.conn_close.error_code           = conn->reason;
          frame.conn_close.frame_type_opt       = 1u; /* presence of frame_type indicates a quic reason */
          frame.conn_close.frame_type           = 0u; /* we do not know the frame in question */
          frame.conn_close.reason_phrase_length = 0u; /* no reason phrase */
        } else {
          frame.conn_close.error_code           = conn->app_reason;
          frame.conn_close.frame_type_opt       = 0u; /* absence of frame_type indicates an application reason */
          frame.conn_close.reason_phrase_length = 0u; /* no reason phrase */
        }

        /* output */
        frame_sz = fd_quic_encode_conn_close_frame( payload_ptr,
                                                    (ulong)( payload_end - payload_ptr ),
                                                    &frame.conn_close );

        if( FD_UNLIKELY( frame_sz == FD_QUIC_PARSE_FAIL ) ) {
          FD_LOG_WARNING(( "%s - fd_quic_encode_crypto_frame failed, but space "
                "should have been available", __func__ ));
          break;
        }

        /* move ptr up */
        payload_ptr  += frame_sz;
        tot_frame_sz += frame_sz;

        /* update packet meta */
        pkt_meta.flags |= FD_QUIC_PKT_META_FLAGS_CLOSE;
      }
    } else {
      /* if handshake data, add it */
      fd_quic_tls_hs_data_t * hs_data   = fd_quic_tls_get_hs_data( conn->tls_hs, (int)enc_level );
      ulong                   hs_offset = 0; /* offset within the current hs_data */

      /* either include handshake data or stream data, but not both */
      if( hs_data ) {
        /* offset within stream */
        ulong offset = conn->hs_sent_bytes[enc_level];

        /* are we the client initial packet? */
        initial_pkt = offset == 0 && !conn->server;

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
            data    = hs_data->data    + hs_offset;
            data_sz = hs_data->data_sz - hs_offset;

            /* build crypto frame */
            frame.crypto.offset      = conn->tx_crypto_offset[enc_level];
            frame.crypto.length      = data_sz;
            frame.crypto.crypto_data = data;

            /* calc size of crypto frame, including */
            frame_sz = fd_quic_encode_footprint_crypto_frame( &frame.crypto );

            /* not enough space? */
            ulong over = 0;
            if( payload_ptr + frame_sz > payload_end ) {
              over = frame_sz - (ulong)( payload_end - payload_ptr );
            }

            if( FD_UNLIKELY( over >= data_sz ) ) {
              break;
            }

            data_sz -= over;
            frame.crypto.length = data_sz;

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

            /* update packet meta */
            pkt_meta.flags          |= FD_QUIC_PKT_META_FLAGS_HS_DATA;
            pkt_meta.range.offset_lo = frame.crypto.offset;
            pkt_meta.range.offset_hi = frame.crypto.offset + data_sz;

            /* move to next hs_data */
            offset       += data_sz;

            /* TODO load more hs_data into a crypto fram, if available
               currently tricky, because encode_crypto_frame copies payload */

            break;
          } else {
            hs_data = fd_quic_tls_get_next_hs_data( conn->tls_hs, hs_data );
          }
        }
      }

      /* are we at application level of encryption? */
      if( enc_level == fd_quic_enc_level_appdata_id ) {
        if( conn->handshake_done ) {
          /* send handshake done frame */
          frame_sz = 1;
          pkt_meta.flags |= FD_QUIC_PKT_META_FLAGS_HS_DONE;
          *(payload_ptr++) = 0x1eu;
          tot_frame_sz++;
        }

        if( conn->flags & FD_QUIC_CONN_FLAGS_MAX_DATA && conn->upd_pkt_number == pkt_number ) {
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

            /* and set actual pkt_number on the stream */
            conn->upd_pkt_number = pkt_number;

            /* set flag on pkt meta */
            pkt_meta.flags          |= FD_QUIC_PKT_META_FLAGS_MAX_DATA;
          } else {
            /* failed to encode - push to next packet */
            conn->upd_pkt_number = pkt_number + 1u;
          }
        }

        if( !hs_data && conn->handshake_complete ) {
          fd_quic_stream_t ** streams         = conn->streams;
          ulong               tot_num_streams = conn->tot_num_streams;
          for( ulong j = 0; j < tot_num_streams; ++j ) {
            fd_quic_stream_t * cur_stream = streams[j];

            /* any unsent data? */
            if( cur_stream->tx_buf.head > cur_stream->tx_sent ) {
              stream = cur_stream;
            }

            if( cur_stream->flags & FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA &&
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
                pkt_meta.flags          |= FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA;
              } else {
                /* failed to encode - push to next packet */
                cur_stream->upd_pkt_number++;
              }
            }
          }

          if( stream ) {

            /* how many bytes are we allowed to send on the stream and on the connection? */
            ulong allowed_stream = stream->tx_max_stream_data - stream->tx_tot_data;
            ulong allowed_conn   = conn->tx_max_data - conn->tx_tot_data;
            ulong allowed        = allowed_conn < allowed_stream ? allowed_conn : allowed_stream;

            /* how much data to send */
            data_sz = stream->tx_buf.head - stream->tx_sent;

            /* offset of the first byte we're sending */
            ulong stream_off = stream->tx_sent;

            /* abide by peer flow control */
            if( data_sz > allowed ) data_sz = allowed;

            /* do we still have data we can send? */
            if( data_sz > 0u ) {
              /* populate frame.stream */
              frame.stream.stream_id = stream->stream_id;

              /* optional fields */
              frame.stream.offset_opt = ( stream_off != 0 );
              frame.stream.offset     = stream_off;

              frame.stream.length_opt = 1; /* always include length */
              frame.stream.length     = data_sz;

              frame.stream.fin_opt    = 0; /* this stream is not finalized */

              /* calc size of stream frame */
              frame_sz = data_sz + fd_quic_encode_footprint_stream_frame( &frame.stream );

              /* over? */
              ulong over = 0;
              if( payload_ptr + frame_sz > payload_end ) {
                over = frame_sz - (ulong)( payload_end - payload_ptr );
              }

              /* adjust to fit */
              data_sz            -= over;
              frame.stream.length = data_sz;

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
              fd_quic_buffer_load( tx_buf, payload_ptr, data_sz );

              /* adjust ptr and size */
              payload_ptr  += data_sz;
              tot_frame_sz += data_sz;

              /* packet metadata */
              pkt_meta.flags          |= FD_QUIC_PKT_META_FLAGS_STREAM;
              pkt_meta.stream_id       = stream->stream_id;
              pkt_meta.range.offset_lo = stream_off;
              pkt_meta.range.offset_hi = stream_off + data_sz;
            }
          }
        }
      }
    }

    /* first initial frame is padded to FD_QUIC_MIN_INITIAL_PKT_SZ
       all short quic packets are padded so 16 bytes of sample are available */
    uint base_pkt_len = (uint)tot_frame_sz + fd_quic_pkt_hdr_pkt_number_len( &pkt_hdr, enc_level ) +
                            FD_QUIC_CRYPTO_TAG_SZ;
    uint padding      = initial_pkt ? FD_QUIC_MIN_INITIAL_PKT_SZ  - base_pkt_len : 0u;

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

    cur_ptr += initial_hdr_sz + 3u - act_hdr_sz;

    /* encode packet header into buffer
       allow `initial_hdr_sz + 3` space for the header... as the payload bytes
       start there */
    ulong rc = fd_quic_pkt_hdr_encode( cur_ptr, act_hdr_sz, &pkt_hdr, enc_level );

    if( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) ) {
      FD_LOG_WARNING(( "%s - fd_quic_pkt_hdr_encode failed, even thought there should "
            "have been enough space", __func__ ));
      return;
    }

    /* add padding */
    if( FD_UNLIKELY( padding ) ) {
      fd_memset( payload_ptr, 0, padding );
      payload_ptr += padding;
    }

    /* everything successful up to here
       encrypt into tx_ptr,tx_ptr+tx_sz */

    /* TODO encrypt */
#if QUIC_DISABLE_CRYPTO
    ulong quic_pkt_sz = (ulong)( payload_ptr - cur_ptr );
    fd_memcpy( conn->tx_ptr, cur_ptr, quic_pkt_sz );
    fd_memset( conn->tx_ptr + quic_pkt_sz, 0, 16 );

    /* update tx_ptr and tx_sz */
    conn->tx_ptr += quic_pkt_sz + 16;
    conn->tx_sz  -= quic_pkt_sz + 16;

    (void)act_hdr_sz;
#else
    ulong  quic_pkt_sz    = (ulong)( payload_ptr - cur_ptr );
    ulong  cipher_text_sz = conn->tx_sz;
    uchar * hdr            = cur_ptr;
    ulong  hdr_sz         = act_hdr_sz;
    uchar * pay            = hdr + hdr_sz;
    ulong  pay_sz         = quic_pkt_sz - hdr_sz;

    fd_quic_crypto_suite_t * suite = conn->suites[enc_level];

    int server = conn->server;

    if( fd_quic_crypto_encrypt( conn->tx_ptr, &cipher_text_sz, hdr, hdr_sz,
          pay, pay_sz, suite, &conn->keys[enc_level][server]  ) != FD_QUIC_SUCCESS ) {
      FD_LOG_ERR(( "%s : fd_quic_crypto_encrypt failed", __func__ ));
      return;
    }

    /* update tx_ptr and tx_sz */
    conn->tx_ptr += cipher_text_sz;
    conn->tx_sz  -= cipher_text_sz;
#endif

    /* TODO if there is space, we can coalesce instead of sending immediately */

    /* update packet metadata with summary info */
    pkt_meta.pkt_number = pkt_number;
    pkt_meta.pn_space   = (uchar)pn_space;
    pkt_meta.enc_level  = (uchar)enc_level;

    DEBUG( {
        printf( "%u compare: %p vs %p\n", __LINE__, (void*)conn->pkt_meta_free, (void*)pm_new );
        printf( "before. conn: %p\n", (void*)conn );
        ulong _ = 0;
        fd_quic_pkt_meta_t * _0 = conn->pkt_meta_free;
        while( _0 ) { _++; _0 = _0->next; }
        printf( "  count: %lu\n", (ulong)_ );
        } )

    /* move the head of free list */
    conn->pkt_meta_free = pm_new->next;

    DEBUG( {
        printf( "after.. conn: %p\n", (void*)conn );
        ulong _ = 0;
        fd_quic_pkt_meta_t * _0 = conn->pkt_meta_free;
        while( _0 ) { _++; _0 = _0->next; }
        printf( "  count: %lu\n", (ulong)_ );
        } )

    /* store the metadata */
    *pm_new = pkt_meta;

    /* local pointers */
    fd_quic_pkt_meta_t ** pkt_meta_tx     = conn->pkt_meta_tx     + enc_level;
    fd_quic_pkt_meta_t ** pkt_meta_tx_end = conn->pkt_meta_tx_end + enc_level;
    if( !*pkt_meta_tx_end ) {
      /* empty list - set head and end */
      *pkt_meta_tx_end = *pkt_meta_tx = pm_new;
      pm_new->next = NULL;
    }  else {
      /* add to end, then make end point to the new entry */
      (*pkt_meta_tx_end)->next = pm_new;
      (*pkt_meta_tx_end)       = pm_new;
      pm_new->next = NULL;
    }

    /* update ack metadata */
    fd_quic_ack_t * cur_ack = conn->acks_tx[enc_level];
    while( cur_ack ) {
      if( cur_ack->tx_pkt_number == pkt_number ) {
        cur_ack->flags |= FD_QUIC_ACK_FLAGS_SENT;
      }

      cur_ack = cur_ack->next;
    }

    /* did we send handshake data? */
    if( pkt_meta.flags & FD_QUIC_PKT_META_FLAGS_HS_DATA ) {
      conn->hs_sent_bytes[enc_level] += data_sz;

      /* bump offset */
      conn->tx_crypto_offset[enc_level] += data_sz;

      /* TODO is hs_sent_bytes the same as tx_crypto_offset? */
    }

    /* did we send stream data? */
    if( pkt_meta.flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
      /* move sent pointer up */
      stream->tx_sent += data_sz;

      /* update flow control */
      stream->tx_tot_data += data_sz;
      conn->tx_tot_data   += data_sz;
    }

    /* did we send handshake-done? */
    if( pkt_meta.flags & FD_QUIC_PKT_META_FLAGS_HS_DONE ) {
      conn->handshake_done = 0;
    }

    /* try to send? */
    fd_quic_tx_buffered( quic, conn );
  }

  DEBUG( printf( "done\n" ); )
}


void
fd_quic_conn_service( fd_quic_t * quic, fd_quic_conn_t * conn, ulong now ) {
  (void)now;

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
        /* call process on TLS */
        int process_rc = fd_quic_tls_process( conn->tls_hs );
        if( process_rc == FD_QUIC_TLS_FAILED ) {
          /* mark as DEAD, and allow it to be cleaned up */
          conn->state             = FD_QUIC_CONN_STATE_DEAD;
          fd_quic_reschedule_conn( conn, now + 1u );
          return;
        }

        /* if we're the server, we send "handshake-done" frame */
        if( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE && conn->server ) {
          conn->handshake_done = 1;

          /* move straight to ACTIVE */
          conn->state = FD_QUIC_CONN_STATE_ACTIVE;

          /* user callback */
          if( conn->quic->cb_conn_new ) {
            conn->quic->cb_conn_new( conn, conn->quic->context );
          }
        }

        /* do we have data to transmit? */
        fd_quic_conn_tx( quic, conn );

        break;
      }

    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
        /* user requested close, and may have set a reason code */
        /* transmit the failure reason */
        fd_quic_conn_tx( quic, conn );

        /* this will make the service call free the connection */
        conn->state = FD_QUIC_CONN_STATE_DEAD;

        break;

    case FD_QUIC_CONN_STATE_ABORT:
        /* transmit the failure reason */
        fd_quic_conn_tx( quic, conn );

        /* this will make the service call free the connection */
        conn->state = FD_QUIC_CONN_STATE_DEAD;

        break;

    case FD_QUIC_CONN_STATE_ACTIVE:
        /* do we have data to transmit? */
        fd_quic_conn_tx( quic, conn );

        break;

    case FD_QUIC_CONN_STATE_DEAD:
      /* fall thru */
    default:
      return;
  }
}

void
fd_quic_conn_free( fd_quic_t * quic, fd_quic_conn_t * conn ) {
  /* remove connection ids from conn_map */

  /* loop over connection ids, and remove each */
  for( ulong j = 0; j < conn->our_conn_id_cnt; ++j ) {
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &conn->our_conn_id[j] );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }
  }

  /* put connection back in free list */
  conn->next  = quic->conns;
  quic->conns = conn;
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
fd_quic_connect( fd_quic_t * quic,
                 uint    dst_ip_addr,
                 ushort    dst_udp_port ) {
  (void)quic;
  (void)dst_ip_addr;
  (void)dst_udp_port;

  /* create conn ids for us and them
     client creates connection id for the peer, peer immediately replaces it */
  fd_quic_conn_id_t our_conn_id  = fd_quic_create_conn_id( quic );
  fd_quic_conn_id_t peer_conn_id = fd_quic_create_conn_id( quic );

  fd_quic_conn_t * conn = fd_quic_create_connection( quic,
                                                     &our_conn_id,
                                                     &peer_conn_id,
                                                     dst_ip_addr,
                                                     dst_udp_port,
                                                     0 /*client*/ );

  if( !conn ) {
    DEBUG(
        printf( "%s : fd_quic_create_connection failed\n", __func__ );
        )
    return NULL;
  }

  /* adjust transport parameters and encode */

  /* the original destination connection id
     only sent by server */
  quic->transport_params.original_destination_connection_id_present = 0;
  quic->transport_params.original_destination_connection_id_len     = 0;

  /* the initial source connection id */
  fd_memcpy( quic->transport_params.initial_source_connection_id,
          conn->initial_source_conn_id.conn_id,
          conn->initial_source_conn_id.sz );
  quic->transport_params.initial_source_connection_id_present = 1;
  quic->transport_params.initial_source_connection_id_len     = our_conn_id.sz;

  /* set up handshake */

  /* quic-tls requires transport parameters */
  uchar transport_params_raw[FD_QUIC_TRANSPORT_PARAMS_RAW_SZ];
  ulong tp_rc = fd_quic_encode_transport_params( transport_params_raw,
                                                  FD_QUIC_TRANSPORT_PARAMS_RAW_SZ,
                                                  &quic->transport_params );
  /* probably means we don't have enough space for all the transport parameters */
  if( FD_UNLIKELY( tp_rc == FD_QUIC_ENCODE_FAIL ) ) {
    DEBUG(
        printf( "%s : fd_quic_encode_transport_params failed\n", __func__ );
        )

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;
    return NULL;
  }

  ulong transport_params_raw_sz = tp_rc;

  /* create a TLS handshake */
  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
                                  quic->quic_tls,
                                  (void*)conn,
                                  0 /*is_server*/,
                                  "localhost", /* TODO does TLS need the hostname here? */
                                  transport_params_raw,
                                  transport_params_raw_sz );
  if( !tls_hs ) {
    DEBUG( printf( "%s : fd_quic_tls_hs_new failed\n", __func__ ); )

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  /* run process tls immediately */
  int process_rc = fd_quic_tls_process( tls_hs );
  if( process_rc == FD_QUIC_TLS_FAILED ) {
    DEBUG(
      fprintf( stderr, "fd_quic_tls_process error at: %s %s %d\n", __func__, __FILE__, __LINE__ );
    )

    /* We haven't sent any data to the peer yet,
       so simply clean up and fail */

    /* shut down tls */
    fd_quic_tls_hs_delete( tls_hs );

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  DEBUG(
      fd_quic_tls_hs_data_t const * hs_data = fd_quic_tls_get_hs_data( tls_hs, 0 );
      printf( "hs_data @ enc_level 0: %p\n", (void*)hs_data );
      fflush( stdout );
      fflush( stdout );
      )

  conn->tls_hs = tls_hs;

  /* generate initial secrets, keys etc */

  /* rfc specifies TLS_AES_128_GCM_SHA256_ID for the suite for initial
     secrets and keys */
  fd_quic_crypto_suite_t * suite = &quic->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];

  /* TODO move this to somewhere more appropriate */
  /* Initial Packets
     from rfc:
     initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
  uchar const * initial_salt    = FD_QUIC_CRYPTO_V1_INITIAL_SALT;
  ulong        initial_salt_sz = FD_QUIC_CRYPTO_V1_INITIAL_SALT_SZ;

  if( fd_quic_gen_initial_secret( &conn->secrets,
                                  initial_salt,     initial_salt_sz,
                                  peer_conn_id.conn_id, peer_conn_id.sz,
                                  suite->hash ) != FD_QUIC_SUCCESS ) {
    /* remove connection from map, and insert into free list */
    DEBUG( fprintf( stderr, "%s: fd_quic_gen_initial_secret failed\n", __func__ ); )

    /* shut down tls */
    fd_quic_tls_hs_delete( tls_hs );

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  if( fd_quic_gen_secrets( &conn->secrets,
                           fd_quic_enc_level_initial_id, /* generate initial secrets */
                           suite->hash ) != FD_QUIC_SUCCESS ) {
    /* remove connection from map, and insert into free list */
    DEBUG( fprintf( stderr, "%s: fd_quic_gen_secrets failed\n", __func__ ); )

    /* shut down tls_hs */
    fd_quic_tls_hs_delete( tls_hs );

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  /* gen initial keys */
  if( fd_quic_gen_keys( &conn->keys[fd_quic_enc_level_initial_id][0],
                        (ulong)suite->key_sz,
                        (ulong)suite->iv_sz,
                        suite->hash,
                        conn->secrets.secret[fd_quic_enc_level_initial_id][0],
                        conn->secrets.secret_sz[fd_quic_enc_level_initial_id][0] )
        != FD_QUIC_SUCCESS ) {
    /* remove connection from map, and insert into free list */
    DEBUG( fprintf( stderr, "%s: fd_quic_gen_keys failed\n", __func__ ); )

    /* shut down tls_hs */
    fd_quic_tls_hs_delete( tls_hs );

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  /* gen initial keys */
  if( fd_quic_gen_keys( &conn->keys[fd_quic_enc_level_initial_id][1],
                        (ulong)suite->key_sz,
                        (ulong)suite->iv_sz,
                        suite->hash,
                        conn->secrets.secret[fd_quic_enc_level_initial_id][1],
                        conn->secrets.secret_sz[fd_quic_enc_level_initial_id][1] )
        != FD_QUIC_SUCCESS ) {
    /* remove connection from map, and insert into free list */
    DEBUG( fprintf( stderr, "%s: fd_quic_gen_keys failed\n", __func__ ); )

    /* shut down tls_hs */
    fd_quic_tls_hs_delete( tls_hs );

    /* remote entry from map */
    fd_quic_conn_entry_t * entry = fd_quic_conn_map_query( quic->conn_map, &our_conn_id );
    if( entry ) {
      fd_quic_conn_map_remove( quic->conn_map, entry );
    }

    /* add to free list */
    conn->next  = quic->conns;
    quic->conns = conn;

    return NULL;
  }

  /* everything initialized */
  return conn;
}


fd_quic_conn_t *
fd_quic_create_connection( fd_quic_t *               quic,
                           fd_quic_conn_id_t const * our_conn_id,
                           fd_quic_conn_id_t const * peer_conn_id,
                           uint                  dst_ip_addr,
                           ushort                  dst_udp_port,
                           int                       server ) {

  /* check current number of connections */
  if( quic->cur_num_conns == quic->max_concur_conns ) {
    DEBUG( printf( "%s : new connection would exceed max_concur_conns\n", __func__ ); )
    return NULL;
  }

  /* fetch top of connection free list */
  fd_quic_conn_t * conn = quic->conns;
  if( conn == NULL ) { /* no free connections */
    DEBUG( printf( "%s : no connections in free list\n", __func__ ); )
    return NULL;
  }

  /* insert into connection map */
  fd_quic_conn_entry_t * insert_entry =
    fd_quic_conn_map_insert( quic->conn_map, our_conn_id );

  /* if insert failed (should be impossible) fail, and do not remove connection
     from free list */
  if( FD_UNLIKELY( insert_entry == NULL ) ) {
    return NULL;
  }

  /* set connection map insert_entry to new connection */
  insert_entry->conn = conn;

  /* remove from free list */
  quic->conns = conn->next;
  conn->next  = NULL;

  /* initialize connection members */
  conn->quic               = quic;
  conn->server             = server;
  conn->version            = 1; /* initially try version 1, even when we support other versions */
  conn->our_conn_id_cnt    = 0; /* set later */
  conn->peer_cnt           = 0;
  conn->cur_conn_id_idx    = 0;
  conn->cur_peer_idx       = 0;
  /* start with smallest value we allow, then allow peer to increase */
  conn->tx_max_datagram_sz = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;
  conn->handshake_complete = 0;
  conn->tls_hs             = NULL; /* created later */

  /* initial max_streams
     we are the client, so start server-initiated at our max-concurrent, and client-initiated at 0
     peer will advertise its configured maximum */
    conn->max_streams[0x00]    = 0;                          /* 0x00 Client-Initiated, Bidirectional */
    conn->max_streams[0x01]    = quic->max_concur_streams;   /* 0x01 Server-Initiated, Bidirectional */
    conn->max_streams[0x02]    = 0;                          /* 0x02 Client-Initiated, Unidirectional */
    conn->max_streams[0x03]    = quic->max_concur_streams;   /* 0x03 Server-Initiated, Unidirectional */

  /* conn->streams initialized inside fd_quic_conn_new */

  /* points to free tx space */
  conn->tx_ptr             = conn->tx_buf;
  conn->tx_sz              = sizeof( conn->tx_buf );

  /* rfc specifies TLS_AES_128_GCM_SHA256_ID for the suite for initial
     secrets and keys */
  conn->suites[fd_quic_enc_level_initial_id]
                           = &quic->crypto_ctx->suites[TLS_AES_128_GCM_SHA256_ID];

  /* stream metadata */
  conn->next_stream_id[0] = 0;
  conn->next_stream_id[1] = 1;
  conn->next_stream_id[2] = 2;
  conn->next_stream_id[3] = 3;

  /* start at our max, peer is allowed to lower */
  conn->max_concur_streams = quic->max_concur_streams;

  /* current number of streams by type is zero */
  fd_memset( &conn->num_streams, 0, sizeof( conn->num_streams ) );

  /* clear peer transport parameters */
  fd_memset( &conn->peer_transport_params, 0, sizeof( conn->peer_transport_params ) );

  /* rfc9000: s12.3:
     Packet numbers in each packet space start at 0.
     Subsequent packets sent in the same packet number space
       MUST increase the packet number by at least 1
     rfc9002: s3
     It is permitted for some packet numbers to never be used, leaving intentional gaps. */
  fd_memset( conn->pkt_number, 0, sizeof( conn->pkt_number ) );

  /* crypto offset for first packet always starts at 0 */
  fd_memset( conn->tx_crypto_offset, 0, sizeof( conn->pkt_number ) );
  fd_memset( conn->rx_crypto_offset, 0, sizeof( conn->pkt_number ) );

  conn->state                = FD_QUIC_CONN_STATE_HANDSHAKE;
  conn->reason               = 0;
  conn->app_reason           = 0;

  /* TODO probably should be the responsibility of the caller */
  /* insert into service queue */
  fd_quic_event_t event[1] = {{ .timeout = 0, .conn = conn }};
  service_queue_insert( quic->service_queue, event );

  /* initialize connection members */
  ulong our_conn_id_idx = 0;
  conn->our_conn_id[our_conn_id_idx] = *our_conn_id;
  conn->our_conn_id_cnt++;
  /* start with minimum supported max datagram */
  /* peers may allow more */
  conn->tx_max_datagram_sz = FD_QUIC_INITIAL_MAX_UDP_PAYLOAD_SZ;

  /* initial source connection id */
  conn->initial_source_conn_id = *our_conn_id;

  /* peer connection id */
  ulong peer_idx = 0;
  conn->peer[peer_idx].conn_id      = *peer_conn_id;
  conn->peer[peer_idx].cur_ip_addr  = dst_ip_addr;
  conn->peer[peer_idx].cur_udp_port = dst_udp_port;
  conn->peer_cnt++;

  /* initialize free list */
  ulong num_pkt_meta = conn->quic->max_in_flight_pkts;
  fd_quic_pkt_meta_t * pkt_meta = conn->pkt_meta_free;
  for( ulong j = 0; j < num_pkt_meta; ++j ) {
    ulong k = j + 1;
    pkt_meta[j].next =  k < num_pkt_meta ? pkt_meta + k : NULL;
  }

  /* initialize other pkt_meta members */
  fd_memset( conn->pkt_meta_tx,     0, sizeof( conn->pkt_meta_tx ) );
  fd_memset( conn->pkt_meta_tx_end, 0, sizeof( conn->pkt_meta_tx_end ) );

  /* initialize free list */
  ulong num_acks = conn->quic->max_in_flight_pkts;
  fd_quic_ack_t * acks = conn->acks_free;
  for( ulong j = 0; j < num_acks; ++j ) {
    ulong k = j + 1;
    acks[j].next =  k < num_acks ? acks + k : NULL;
  }

  /* initialize other ack members */
  fd_memset( conn->acks_tx,     0, sizeof( conn->acks_tx ) );
  fd_memset( conn->acks_tx_end, 0, sizeof( conn->acks_tx_end ) );

  /* return number of bytes consumed */
  return conn;
}

extern inline FD_FN_CONST
int
fd_quic_handshake_complete( fd_quic_conn_t * conn );


/* set callback for receiving new connection notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
extern inline
void
fd_quic_set_cb_conn_new( fd_quic_t * quic, fd_quic_cb_conn_new_t cb );


/* set callback for receiving connection handshake complete notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
extern inline
void
fd_quic_set_cb_conn_handshake_complete( fd_quic_t * quic, fd_quic_cb_conn_handshake_complete_t cb );


/* set callback for receiving connection finalized notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
extern inline
void
fd_quic_set_cb_conn_final( fd_quic_t * quic, fd_quic_cb_conn_final_t cb );


/* set context for connection callbacks */
extern inline
void
fd_quic_set_conn_cb_context( fd_quic_t * quic, void * context );


/* set context for stream callbacks */
extern inline
void
fd_quic_set_stream_cb_context( fd_quic_stream_t * stream, void * stream_context );


ulong
fd_quic_get_next_wakeup( fd_quic_t * quic ) {
  ulong t = ~(ulong)0;
  if( service_queue_cnt( quic->service_queue ) ) {
    t = quic->service_queue[0].timeout;
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

  return 0;
}

void
fd_quic_reclaim_pkt_meta( fd_quic_conn_t *     conn,
                          fd_quic_pkt_meta_t * pkt_meta,
                          uint                 enc_level ) {
  uint  flags      = pkt_meta->flags;
  ulong pkt_number = pkt_meta->pkt_number;

  if( flags & FD_QUIC_PKT_META_FLAGS_HS_DATA ) {
    /* hs_data is being acked
       TODO we should free data here */
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
    conn->flags &= ~FD_QUIC_CONN_FLAGS_MAX_DATA;
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA ) {
    /* find stream */
    fd_quic_stream_t *  stream          = NULL;
    fd_quic_stream_t ** streams         = conn->streams;
    ulong               tot_num_streams = conn->tot_num_streams;
    for( ulong j = 0; j < tot_num_streams; ++j ) {
      if( streams[j]->stream_id == pkt_meta->stream_id ) {
        stream = streams[j];
        break;
      }
    }

    if( stream ) {
      stream->flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
    }
  }

  if( flags & FD_QUIC_PKT_META_FLAGS_STREAM ) {
    fd_quic_range_t range = pkt_meta->range;

    /* find stream */
    fd_quic_stream_t *  stream          = NULL;
    fd_quic_stream_t ** streams         = conn->streams;
    ulong               tot_num_streams = conn->tot_num_streams;
    for( ulong j = 0; j < tot_num_streams; ++j ) {
      if( streams[j]->stream_id == pkt_meta->stream_id ) {
        stream = streams[j];
        break;
      }
    }

    if( FD_LIKELY( stream ) ) {

      ulong tx_tail = stream->tx_buf.tail;
      ulong tx_sent = stream->tx_sent;

      /* ignore bytes which were already acked */
      if( range.offset_lo < tx_tail ) range.offset_lo = tx_tail;

      /* if they ack bytes we didn't send, that's a protocol error */
      /* TODO ensure this is the correct reason */
      if( range.offset_hi < tx_sent ) {
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

        /* move up tail, and adjust to maintain circular queue invariants, and send
           max_data and max_stream_data, if necessary */
        if( tx_tail > stream->tx_buf.tail ) {
          stream->tx_buf.tail = tx_tail;

          /* if we have data to send, reschedule */
          if( fd_quic_buffer_avail( &stream->tx_buf ) ) {
            fd_quic_reschedule_conn( conn, conn->quic->now_fn( conn->quic->now_ctx ) + 1ul );
          }
        }

        /* we could retransmit (timeout) the bytes which have not been acked (by implication) */
      }
    }
  }

  /* max_stream_data */
  if( flags & FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA ) {
    ulong               tot_num_streams = conn->tot_num_streams;
    fd_quic_stream_t ** streams         = conn->streams;
    for( ulong j = 0; j < tot_num_streams; ++j ) {
      fd_quic_stream_t * stream = streams[j];
      if( stream->upd_pkt_number == pkt_number ) {
        stream->flags &= ~FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
      }
    }
  }

  /* acks */
  if( flags & FD_QUIC_PKT_META_FLAGS_ACK ) {
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
    if( cur_ack ) {
      if( cur_ack->tx_pkt_number == pkt_number ) {
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
}


/* process ack range
   applies to pkt_number in [largest_ack - first_ack_range, largest_ack] */
void
fd_quic_process_ack_range( fd_quic_conn_t * conn,
                           uint             enc_level,
                           ulong            largest_ack,
                           ulong            first_ack_range ) {
  /* loop thru all packet metadata, and process individual metadata */

  /* inclusive range */
  ulong hi = largest_ack;
  ulong lo = largest_ack - first_ack_range;

  /* start at oldest */
  fd_quic_pkt_meta_t * pkt_meta = conn->pkt_meta_tx[enc_level];
  fd_quic_pkt_meta_t * prior    = NULL;
  while( pkt_meta ) {
    if( pkt_meta->pkt_number < lo ) {
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
      if( prior == NULL ) {
        if( pkt_meta_next == NULL ) {
          /* at end... then head = end = NULL */
          conn->pkt_meta_tx_end[enc_level] = NULL;
        }

        /* at head... move it to next */
        conn->pkt_meta_tx[enc_level] = pkt_meta_next;
      } else {
        if( pkt_meta->next == NULL ) {
          /* we're removing the last, so move end */
          conn->pkt_meta_tx_end[enc_level] = prior;
        }

        /* not head, make prior point to next */
        prior->next = pkt_meta_next;
      }

      /* put pkt_meta back in free list */
      pkt_meta->next      = conn->pkt_meta_free;
      conn->pkt_meta_free = pkt_meta;

      /* we removed one, so keep prior the same and move pkt_meta up */
      pkt_meta = pkt_meta_next;
      continue;
    }

    prior               = pkt_meta;
    pkt_meta            = pkt_meta_next;
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

  /* ack packets are not ack-eliciting (they are acked with other things) */

  /* process ack range
     applies to pkt_number in [largest_ack - first_ack_range, largest_ack] */
  fd_quic_process_ack_range( context.conn, enc_level, data->largest_ack, data->first_ack_range );

  uchar const * p_str = p;
  uchar const * p_end = p + p_sz;

  ulong ack_range_count = data->ack_range_count;

  ulong cur_pkt_number = data->largest_ack - data->first_ack_range - 1u;

  /* walk thru ack ranges */
  for( ulong j = 0; j < ack_range_count; ++j ) {
    if( FD_UNLIKELY(  p_end <= p ) ) return FD_QUIC_PARSE_FAIL;

    fd_quic_ack_range_frag_t ack_range[1];
    ulong rc = fd_quic_decode_ack_range_frag( ack_range, p, (ulong)( p_end - p ) );
    if( rc == FD_QUIC_PARSE_FAIL ) return FD_QUIC_PARSE_FAIL;

    /* the number of packet numbers to skip (they are not being acked) */
    cur_pkt_number -= ack_range->gap;

    /* process ack range */
    fd_quic_process_ack_range( context.conn, enc_level, cur_pkt_number, ack_range->length );

    /* adjust for next range */
    cur_pkt_number -= ack_range->length - 1u;

    p += rc;
  }

  /* ECN counts
     we currently ignore them, but we must process them to get to the following bytes */
  if( data->type & 1u ) {
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
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_stream_frame(
    void *                       vp_context,
    fd_quic_stream_frame_t *     data,
    uchar const *                p,
    ulong                       p_sz ) {
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

  /* find stream */
  fd_quic_stream_t *  stream = NULL;
  fd_quic_stream_t ** streams = context.conn->streams;
  for( ulong j = 0; j < context.conn->tot_num_streams; ++j ) {
    if( stream_id == streams[j]->stream_id ) {
      stream = streams[j];
      break;
    }
    if( streams[j]->stream_id == FD_QUIC_STREAM_ID_UNUSED ) {
      stream = streams[j];
    }
  }

  if( !stream || stream->stream_id == FD_QUIC_STREAM_ID_UNUSED ) {
    /* No free streams - fail */
    ulong max_stream_id = context.conn->max_streams[type];
    if( FD_UNLIKELY( stream_id > max_stream_id ) ) {
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );

      /* since we're terminating the connection, don't parse more */
      return FD_QUIC_PARSE_FAIL;
    }
  }

  if( FD_UNLIKELY( !stream ) ) {
    /* no free streams - concurrent max should handle this */
    FD_LOG_WARNING(( "insufficient space for incoming stream, yet concurrent max not exceeded" ));

    fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_INTERNAL_ERROR );

    /* since we're terminating the connection, don't parse more */
    return FD_QUIC_PARSE_FAIL;
  }

  /* new stream - peer initiated */
  if( stream->stream_id == FD_QUIC_STREAM_ID_UNUSED ) {
    /* initialize stream members */

    /* we need to know if client-initiated or server-initiated
       we know peer initiated, so: */
    uint initiator = !context.conn->server;

    /* client chosen stream id must match type */
    uint stream_id_initiator = ( stream_id >> 1u ) & 1u;
    if( FD_UNLIKELY( stream_id_initiator != initiator ) ) {
      FD_LOG_WARNING(( "Peer requested invalid stream id" ));
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );

      /* since we're terminating the connection, don't parse more */
      return FD_QUIC_PARSE_FAIL;
    }

    /* bidirectional? */
    uint bidir = ( stream_id >> 1u ) & 1u;

    /* if unidir, we can't send - since peer initiated */
    /* if bidir we can only send up to the peer's advertized limit */
    ulong tx_max_stream_data = bidir ?
                context.conn->tx_initial_max_stream_data_bidi_local : 0;

    stream->conn        = context.conn;
    stream->stream_id   = stream_id;

    stream->context     = NULL; /* TODO where do we get this from? */

    stream->tx_buf.head = 0; /* first unused byte of tx_buf */
    stream->tx_buf.tail = 0; /* first unacked (used) byte of tx_buf */
    stream->tx_sent     = 0; /* first unsent byte of tx_buf */

    stream->flags       = 0;

    /* flow control */
    stream->tx_max_stream_data = tx_max_stream_data;
    stream->tx_tot_data        = 0;

    stream->rx_max_stream_data = context.conn->stream_rx_buf_sz;
    stream->rx_tot_data        = 0;
  }

  /* TODO pass the fin bit to the user here? */
  /* or provide in API */

  /* TODO if fin bit set, store the final size */

  /* TODO could allow user to cancel ack for this packet */

  /* determine whether any of these bytes were already received
     or whether these bytes are out of order */

  ulong exp_offset = stream->rx_tot_data; /* we expect the next byte */

  /* do we have at least one byte we can deliver? */
  if( FD_LIKELY( offset <= exp_offset && offset + data_sz > exp_offset ) ) {
    if( FD_UNLIKELY( stream->flags & FD_QUIC_STREAM_FLAGS_RX_FIN ) ) {
      /* this stream+direction was already FIN... protocol error */
      /* TODO might be a stream error instead */
      fd_quic_conn_error( context.conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
      return FD_QUIC_PARSE_FAIL;
    }

    ulong skip = exp_offset - offset; /* skip already delivered bytes */

    ulong delivered = data_sz - skip;

    if( FD_LIKELY( context.quic->cb_stream_receive ) ) {
      context.quic->cb_stream_receive( stream,
                                       stream->context,
                                       p + skip, delivered,
                                       exp_offset );

    }

    /* get connection */
    fd_quic_conn_t * conn = stream->conn;

    /* update data received */
    stream->rx_tot_data = exp_offset + delivered;
    conn->rx_tot_data  += delivered;

    /* send max_stream_data and max_data updates */
    /* TODO when RX is buffered, this will change */
    stream->rx_max_stream_data += delivered;
    conn->rx_max_data          += delivered;

    /* set max_data and max_data_frame to go out next packet */
    uint pn_space = fd_quic_enc_level_to_pn_space( fd_quic_enc_level_appdata_id );
    stream->upd_pkt_number = conn->upd_pkt_number = conn->pkt_number[pn_space];

    stream->flags |= FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA;
    conn->flags   |= FD_QUIC_CONN_FLAGS_MAX_DATA;

    /* ensure we ack the packet */
    fd_quic_t * quic = context.quic;
    fd_quic_reschedule_conn( context.conn, quic->now_fn( quic->now_ctx ) + 1 );

    if( data->fin_opt ) {
      stream->flags |= FD_QUIC_STREAM_FLAGS_RX_FIN;
      if( stream->flags & FD_QUIC_STREAM_FLAGS_TX_FIN ||
          stream->stream_id & ( FD_QUIC_TYPE_UNIDIR << 1u ) ) {
        /* TODO rename FD_QUIC_NOTIFY_END to FD_QUIC_STREAM_NOTIFY_END et al */
        context.quic->cb_stream_notify( stream, stream->context, FD_QUIC_NOTIFY_END );

        /* free the stream */
        stream->stream_id = FD_QUIC_STREAM_ID_UNUSED;
      }
    }
  } else {
    if( offset > exp_offset ) {
      /* TODO technically "future" out of order bytes should be counted,
         and if within our published max_stream_data (and max_data) should be stored
         in a reorder buffer. */
      /* for now, we cancel the ack */
      context.pkt->ack_flag |= ACK_FLAG_CANCEL;
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

  ulong stream_id  = data->stream_id;

  /* find stream */
  fd_quic_stream_t *  stream  = NULL;
  fd_quic_stream_t ** streams = context.conn->streams;
  for( ulong j = 0; j < context.conn->tot_num_streams; ++j ) {
    if( stream_id == streams[j]->stream_id ) {
      stream = streams[j];
      break;
    }
  }

  if( FD_UNLIKELY( !stream ) ) return 0;

  ulong tx_max_stream_data  = stream->tx_max_stream_data;
  ulong new_max_stream_data = data->max_stream_data;

  /* max data is only allowed to increase the limit. Transgressing frames
     are silently ignored */
  stream->tx_max_stream_data = new_max_stream_data > tx_max_stream_data ? new_max_stream_data : tx_max_stream_data;

  return 0;
}

static ulong
fd_quic_frame_handle_max_streams_frame(
    void * context,
    fd_quic_max_streams_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_data_blocked_frame(
    void * context,
    fd_quic_data_blocked_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_stream_data_blocked_frame(
    void * context,
    fd_quic_stream_data_blocked_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_streams_blocked_frame(
    void * context,
    fd_quic_streams_blocked_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_new_conn_id_frame(
    void * context,
    fd_quic_new_conn_id_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
  return FD_QUIC_PARSE_FAIL;
}

static ulong
fd_quic_frame_handle_retire_conn_id_frame(
    void * context,
    fd_quic_retire_conn_id_frame_t * data,
    uchar const * p,
    ulong p_sz) {
  (void)context;
  (void)data;
  (void)p;
  (void)p_sz;
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

static ulong
fd_quic_frame_handle_conn_close_frame(
    void *                       vp_context,
    fd_quic_conn_close_frame_t * data,
    uchar const *                p,
    ulong                       p_sz ) {
  (void)data;
  (void)p;
  (void)p_sz;
  fd_quic_frame_context_t context = *(fd_quic_frame_context_t*)vp_context;

  /* ack-eliciting */
  context.pkt->ack_flag |= ACK_FLAG_RQD;

  /* frame type 0x1c means no error, or only error at quic level
     frame type 0x1d means error at application layer
     TODO provide APP with this info */
  (void)context;
  DEBUG(
      printf( "%s : peer requested close\n", __func__ );
      )

  switch( context.conn->state ) {
    case FD_QUIC_CONN_STATE_ABORT:
    case FD_QUIC_CONN_STATE_CLOSE_PENDING:
      return 0u;

    default:
      context.conn->state = FD_QUIC_CONN_STATE_PEER_CLOSE;
  }

  return 0u;
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

  /* servers must treat receipt of HANDSHAKE_DONE as a protocol violation */
  if( FD_UNLIKELY( conn->server ) ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION );
    return FD_QUIC_PARSE_FAIL;
  }

  /* either we treat this as a fatal error, or just warn
     if we don't tear down the connection we must move to ACTIVE */
  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE ) ) {
    FD_LOG_WARNING(( "%s : handshake done frame received, but not in handshake complete state", __func__ ));
  }


  /* we shouldn't be receiving this unless handshake is complete */
  conn->state = FD_QUIC_CONN_STATE_ACTIVE;

  /* user callback */
  if( FD_LIKELY( conn->quic->cb_conn_new ) ) {
    conn->quic->cb_conn_new( conn, conn->quic->context );
  }

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
  fd_quic_t * quic = conn->quic;
  fd_quic_reschedule_conn( conn, quic->now_fn( quic->now_ctx ) + 1u );
}

