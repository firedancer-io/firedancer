#ifndef HEADER_fd_src_waltz_quic_fd_quic_private_h
#define HEADER_fd_src_waltz_quic_fd_quic_private_h

#include "fd_quic.h"
#include "fd_quic_conn.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_pkt_meta.h"
#include "fd_quic_tx_streams.h"
#include "templ/fd_quic_transport_params.h"
#include "templ/fd_quic_union.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "tls/fd_quic_tls.h"

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* FD_QUIC_DISABLE_CRYPTO: set to 1 to disable packet protection and
   encryption.  Only intended for testing.
   FIXME not fully implemented (#256) */
#ifndef FD_QUIC_DISABLE_CRYPTO
#define FD_QUIC_DISABLE_CRYPTO 0
#endif

/* FD_QUIC_MAGIC is used to signal the layout of shared memory region
   of an fd_quic_t. */

#define FD_QUIC_MAGIC (0xdadf8cfa01cc5460UL)

/* events for time based processing */
struct fd_quic_event {
  ulong            timeout;

  fd_quic_conn_t * conn; /* connection or NULL */
  /* possibly "type", etc., for other kinds of service */
};
typedef struct fd_quic_event fd_quic_event_t;

struct fd_quic_frame_context {
  fd_quic_t *      quic;
  fd_quic_conn_t * conn;
  fd_quic_pkt_t *  pkt;
};

typedef struct fd_quic_frame_context fd_quic_frame_context_t;

/* fd_quic_state_t is the internal state of an fd_quic_t.  Valid for
   lifetime of join. */

struct __attribute__((aligned(16UL))) fd_quic_state_private {
  ulong now; /* the time we entered into fd_quic_service, or fd_quic_aio_cb_receive */

  /* Pointer to TLS state (part of quic memory region) */

  fd_quic_tls_t * tls;

  /* transport_params: Template for QUIC-TLS transport params extension.
     Contains a mix of mutable and immutable fields.  Immutable fields
     are set on join.  Mutable fields may be modified during packet
     processing.  Any code using this struct must ensure that the
     mutable fields are cleared before using (otherwise would leak a
     side channel).

     Mutable fields include:
     - original_destination_connection_id
     - initial_source_conn_id */

  fd_quic_transport_params_t transport_params;

  /* Various internal state */

  fd_quic_conn_t *           conns;          /* fd_pool */
  fd_quic_conn_map_t *       conn_map;       /* map connection ids -> connection */
  fd_quic_event_t *          service_queue;  /* priority queue of connections by service time */
  fd_quic_tx_stream_pool_t * tx_streams;
  fd_quic_pkt_meta_list_t    pkt_meta_free[1];
  fd_quic_pkt_meta_t *       pkt_meta_pool;

  fd_rng_t                _rng[1];        /* random number generator */

  /* flow control - configured initial limits */
  ulong initial_max_data;           /* directly from transport params */
  ulong initial_max_stream_data[4]; /* from 4 transport params indexed by stream type */

  /* next_ephem_udp_port: Next ephemeral UDP port to allocate */
  ushort next_ephem_udp_port;

  /* last arp/routing tables update */
  ulong ip_table_upd;

  /* secret for generating RETRY tokens */
  uchar retry_secret[FD_QUIC_RETRY_SECRET_SZ];
  uchar retry_iv    [FD_QUIC_RETRY_IV_SZ];

  ulong        stream_window_cnt;  /* max deliverable streams across all conns */
  ulong        defrag_stream_id;   /* stream_id being currently defragged */
  ulong        defrag_offset;      /* all bytes before this offset were previously received */

  /* Scratch space for packet protection */
  uchar crypt_scratch[FD_QUIC_MTU];
};

/* FD_QUIC_STATE_OFF is the offset of fd_quic_state_t within fd_quic_t. */
#define FD_QUIC_STATE_OFF (fd_ulong_align_up( sizeof(fd_quic_t), alignof(fd_quic_state_t) ))

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
# define ACK_FLAG_RQD     1 /* ack-eliciting */
# define ACK_FLAG_CANCEL  2 /* do not send ACK to cause peer to retransmit */
};

FD_PROTOTYPES_BEGIN

/* fd_quic_get_state returns a pointer to private state area given a
   pointer to fd_quic_t.  Const func, guaranteed to not access memory. */

FD_FN_CONST static inline fd_quic_state_t *
fd_quic_get_state( fd_quic_t * quic ) {
  return (fd_quic_state_t *)( (ulong)quic + FD_QUIC_STATE_OFF );
}

FD_FN_CONST static inline fd_quic_state_t const *
fd_quic_get_state_const( fd_quic_t const * quic ) {
  return (fd_quic_state_t const *)( (ulong)quic + FD_QUIC_STATE_OFF );
}

/* fd_quic_conn_service is called periodically to perform pending
   operations and time based operations.

   args
     quic        managing quic
     conn        connection to service */
void
fd_quic_conn_service( fd_quic_t *      quic,
                      fd_quic_conn_t * conn );

/* reschedule a connection */
void
fd_quic_reschedule_conn( fd_quic_conn_t * conn,
                         ulong            timeout );

/* Memory management **************************************************/

fd_quic_conn_t *
fd_quic_conn_create( fd_quic_t *               quic,
                     ulong                     our_conn_id,
                     fd_quic_conn_id_t const * peer_conn_id,
                     uint                      dst_ip_addr,
                     ushort                    dst_udp_port,
                     int                       server,
                     uint                      version );

/* fd_quic_conn_free frees up resources related to the connection and
   returns it to the connection free list. */
void
fd_quic_conn_free( fd_quic_t *      quic,
                   fd_quic_conn_t * conn );

/* Callbacks provided by fd_quic **************************************/

/* used by quic to receive data from network */
int
fd_quic_aio_cb_receive( void *                    context,
                        fd_aio_pkt_info_t const * batch,
                        ulong                     batch_sz,
                        ulong *                   opt_batch_idx,
                        int                       flush );

/* declare callbacks from quic-tls into quic */
int
fd_quic_tls_cb_client_hello( fd_quic_tls_hs_t * hs,
                             void *             context );

int
fd_quic_tls_cb_handshake_data( fd_quic_tls_hs_t * hs,
                               void *             context,
                               uint               enc_level,
                               uchar const *      data,
                               ulong              data_sz );

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

void
fd_quic_tls_cb_peer_params( void *        context,
                            uchar const * peer_tp_enc,
                            ulong         peer_tp_enc_sz );

/* Helpers for calling callbacks **************************************/

static inline ulong
fd_quic_now( fd_quic_t * quic ) {
  return quic->cb.now( quic->cb.now_ctx );
}

static inline void
fd_quic_cb_conn_new( fd_quic_t *      quic,
                     fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_new || conn->called_conn_new ) ) {
    return;
  }

  quic->cb.conn_new( conn, quic->cb.quic_ctx );
  conn->called_conn_new = 1;
}

static inline void
fd_quic_cb_conn_hs_complete( fd_quic_t *      quic,
                             fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_hs_complete ) ) return;
  quic->cb.conn_hs_complete( conn, quic->cb.quic_ctx );
}

static inline void
fd_quic_cb_conn_final( fd_quic_t *      quic,
                       fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_final || !conn->called_conn_new ) ) return;
  quic->cb.conn_final( conn, quic->cb.quic_ctx );
}

uint
fd_quic_tx_buffered_raw( fd_quic_t *   quic,
                         uchar const * tx,
                         ulong         tx_sz,
                         uchar const   dst_mac_addr[ static 6 ],
                         ushort *      ipv4_id,
                         uint          dst_ipv4_addr,
                         ushort        src_udp_port,
                         ushort        dst_udp_port,
                         int           flush );

void
fd_quic_pkt_meta_retry( fd_quic_t *          quic,
                        fd_quic_conn_t *     conn,
                        int                  force,
                        uint                 arg_enc_level );

/* reclaim resources associated with packet metadata
   this is called in response to received acks */
void
fd_quic_reclaim_pkt_meta( fd_quic_conn_t *     conn,
                          fd_quic_pkt_meta_t * pkt_meta,
                          uint                 enc_level );

ulong
fd_quic_send_retry( fd_quic_t *                  quic,
                    fd_quic_pkt_t *              pkt,
                    fd_quic_conn_id_t const *    orig_dst_conn_id,
                    fd_quic_conn_id_t const *    new_conn_id,
                    uchar const                  dst_mac_addr_u6[ 6 ],
                    uint                         dst_ip_addr,
                    ushort                       dst_udp_port );

ulong
fd_quic_process_quic_packet_v1( fd_quic_t *     quic,
                                fd_quic_pkt_t * pkt,
                                uchar *         cur_ptr,
                                ulong           cur_sz );

ulong
fd_quic_handle_v1_initial( fd_quic_t *               quic,
                           fd_quic_conn_t **         p_conn,
                           fd_quic_pkt_t *           pkt,
                           fd_quic_conn_id_t const * conn_id,
                           uchar *                   cur_ptr,
                           ulong                     cur_sz );

ulong
fd_quic_handle_v1_one_rtt( fd_quic_t *      quic,
                           fd_quic_conn_t * conn,
                           fd_quic_pkt_t *  pkt,
                           uchar *          cur_ptr,
                           ulong            cur_sz );

/* fd_quic_handle_v1_frame is the primary entrypoint for handling of
   incoming QUIC frames.  {quic,conn,pkt} identify the frame context.
   Memory region [frame_ptr,frame_ptr+frame_sz) contains the serialized
   QUIC frame (may contain arbitrary zero padding at the beginning).

   Returns value in (0,buf_sz) if the frame was successfully processed.
   Returns FD_QUIC_PARSE_FAIL if the frame was inherently malformed.
   Returns 0 or value in [buf_sz,ULONG_MAX) in case of a protocol
   violation. */

ulong
fd_quic_handle_v1_frame( fd_quic_t *       quic,
                         fd_quic_conn_t *  conn,
                         fd_quic_pkt_t *   pkt,
                         uint              pkt_type,
                         uchar const *     frame_ptr,
                         ulong             frame_sz );

/* fd_quic_gen_frames generates payloads for outgoing QUIC packets.
   Generates, ACK, CONN_CLOSE, CRYPTO, HANDSHAKE_DONE, MAX_DATA,
   MAX_STREAMS, PING, and STREAM frames.  (in that order)

   The range [payload_ptr,return value) contains generated QUIC frames.
   The largest possible range is [payload_ptr,payload_end).
   (payload_end-payload_ptr) must be at least 128 bytes.

   If no packets could be generated (due to insufficient buffer space
   or lack of data to send) returns NULL. */

uchar *
fd_quic_gen_frames( fd_quic_conn_t *     conn,
                    uchar *              payload_ptr,
                    uchar *              payload_end,
                    uint                 enc_level,
                    fd_quic_pkt_meta_t * pkt_meta,
                    ulong                pkt_number,
                    ulong                now );

/* fd_quic_conn_error sets the connection state to aborted.  This does
   not destroy the connection object.  Rather, it will eventually cause
   the connection to be freed during a later fd_quic_service call.
   reason is a RFC 9000 QUIC error code.  error_line is a implementation
   defined error code for internal use (usually the source line of code
   in fd_quic.c) */

void
fd_quic_conn_error( fd_quic_conn_t * conn,
                    uint             reason,
                    uint             error_line );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_private_h */
