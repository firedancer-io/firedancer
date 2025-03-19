#ifndef HEADER_fd_src_waltz_quic_fd_quic_private_h
#define HEADER_fd_src_waltz_quic_fd_quic_private_h

#include "fd_quic.h"
#include "templ/fd_quic_transport_params.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_stream.h"
#include "log/fd_quic_log_tx.h"
#include "fd_quic_pkt_meta.h"
#include "tls/fd_quic_tls.h"
#include "fd_quic_stream_pool.h"
#include "fd_quic_pretty_print.h"

#include "../../util/log/fd_dtrace.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* Handshake allocator pool */
#define POOL_NAME fd_quic_tls_hs_pool
#define POOL_T    fd_quic_tls_hs_t
#include "../../util/tmpl/fd_pool.c"

/* FD_QUIC_DISABLE_CRYPTO: set to 1 to disable packet protection and
   encryption.  Only intended for testing. */
#ifndef FD_QUIC_DISABLE_CRYPTO
#define FD_QUIC_DISABLE_CRYPTO 0
#endif

#define FD_QUIC_PKT_NUM_UNUSED  (~0ul)
#define FD_QUIC_PKT_NUM_PENDING (~1ul)

/* FD_QUIC_MAGIC is used to signal the layout of shared memory region
   of an fd_quic_t. */

#define FD_QUIC_MAGIC (0xdadf8cfa01cc5460UL)

/* FD_QUIC_SVC_{...} specify connection timer types. */

#define FD_QUIC_SVC_INSTANT (0U)  /* as soon as possible */
#define FD_QUIC_SVC_ACK_TX  (1U)  /* within local max_ack_delay (ACK TX coalesce) */
#define FD_QUIC_SVC_WAIT    (2U)  /* within min(idle_timeout, peer max_ack_delay) */
#define FD_QUIC_SVC_CNT     (3U)  /* number of FD_QUIC_SVC_{...} levels */

/* fd_quic_svc_queue_t is a simple doubly linked list. */

struct fd_quic_svc_queue {
  /* FIXME track count */ // uint cnt;
  uint head;
  uint tail;
};

typedef struct fd_quic_svc_queue fd_quic_svc_queue_t;


/* fd_quic_state_t is the internal state of an fd_quic_t.  Valid for
   lifetime of join. */

struct __attribute__((aligned(16UL))) fd_quic_state_private {
  /* Flags */
  ulong flags;

  ulong now; /* the time we entered into fd_quic_service, or fd_quic_aio_cb_receive */

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

  ulong max_inflight_pkt_cnt_conn; /* per-conn max, computed from limits */

  /* Various internal state */

  fd_quic_log_tx_t        log_tx[1];
  uint                    free_conn_list; /* free list of unused connections */
  fd_quic_conn_map_t *    conn_map;       /* map connection ids -> connection */
  fd_quic_tls_t           tls[1];
  fd_quic_tls_hs_t *      hs_pool;
  fd_quic_stream_pool_t * stream_pool;    /* stream pool, nullable */
  fd_quic_pkt_meta_t    * pkt_meta_pool;
  fd_rng_t                _rng[1];        /* random number generator */
  fd_quic_svc_queue_t     svc_queue[ FD_QUIC_SVC_CNT ]; /* dlists */
  ulong                   svc_delay[ FD_QUIC_SVC_CNT ]; /* target service delay */

  /* need to be able to access connections by index */
  ulong                   conn_base;      /* address of array of all connections */
                                          /* not using fd_quic_conn_t* to avoid confusion */
                                          /* use fd_quic_conn_at_idx instead */
  ulong                   conn_sz;        /* size of one connection element */

  /* flow control - configured initial limits */
  ulong initial_max_data;           /* directly from transport params */
  ulong initial_max_stream_data[4]; /* from 4 transport params indexed by stream type */

  /* last arp/routing tables update */
  ulong ip_table_upd;

  /* state for QUIC sampling */
  fd_quic_pretty_print_t quic_pretty_print;

  /* secret for generating RETRY tokens */
  uchar retry_secret[FD_QUIC_RETRY_SECRET_SZ];
  uchar retry_iv    [FD_QUIC_RETRY_IV_SZ];

  /* Scratch space for packet protection */
  uchar                   crypt_scratch[FD_QUIC_MTU];
};

/* FD_QUIC_STATE_OFF is the offset of fd_quic_state_t within fd_quic_t. */
#define FD_QUIC_STATE_OFF (fd_ulong_align_up( sizeof(fd_quic_t), alignof(fd_quic_state_t) ))

struct fd_quic_pkt {
  fd_ip4_hdr_t       ip4[1];
  fd_udp_hdr_t       udp[1];

  /* the following are the "current" values only. There may be more QUIC packets
     in a UDP datagram */
  ulong              pkt_number;  /* quic packet number currently being decoded/parsed */
  ulong              rcv_time;    /* time packet was received */
  uint               enc_level;   /* encryption level */
  uint               datagram_sz; /* length of the original datagram */
  uint               ack_flag;    /* ORed together: 0-don't ack  1-ack  2-cancel ack */
# define ACK_FLAG_RQD     1
# define ACK_FLAG_CANCEL  2

  ulong              rtt_pkt_number; /* packet number used for rtt */
  ulong              rtt_ack_time;
  ulong              rtt_ack_delay;
};

struct fd_quic_frame_ctx {
  fd_quic_t *      quic;
  fd_quic_conn_t * conn;
  fd_quic_pkt_t *  pkt;
};

typedef struct fd_quic_frame_ctx fd_quic_frame_ctx_t;

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
     conn        connection to service
     now         the current timestamp */
void
fd_quic_conn_service( fd_quic_t *      quic,
                      fd_quic_conn_t * conn,
                      ulong            now );

/* fd_quic_svc_schedule installs a connection timer.  svc_type is in
   [0,FD_QUIC_SVC_CNT) and specifies the timer delay.  Lower timers
   override higher ones. */

void
fd_quic_svc_schedule( fd_quic_state_t * state,
                      fd_quic_conn_t *  conn,
                      uint              svc_type );

static inline void
fd_quic_svc_schedule1( fd_quic_conn_t * conn,
                       uint             svc_type ) {
  fd_quic_svc_schedule( fd_quic_get_state( conn->quic ), conn, svc_type );
}

/* Memory management **************************************************/

fd_quic_conn_t *
fd_quic_conn_create( fd_quic_t *               quic,
                     ulong                     our_conn_id,
                     fd_quic_conn_id_t const * peer_conn_id,
                     uint                      peer_ip_addr,
                     ushort                    peer_udp_port,
                     uint                      self_ip_addr,
                     ushort                    self_udp_port,
                     int                       server );

/* fd_quic_conn_free frees up resources related to the connection and
   returns it to the connection free list. */
void
fd_quic_conn_free( fd_quic_t *      quic,
                   fd_quic_conn_t * conn );

void
fd_quic_tx_stream_free( fd_quic_t *        quic,
                        fd_quic_conn_t *   conn,
                        fd_quic_stream_t * stream,
                        int                code );

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
  if( conn->called_conn_new ) return;
  conn->called_conn_new = 1;
  if( !quic->cb.conn_new ) return;

  quic->cb.conn_new( conn, quic->cb.quic_ctx );
}

static inline void
fd_quic_cb_conn_hs_complete( fd_quic_t *      quic,
                             fd_quic_conn_t * conn ) {
  if( !quic->cb.conn_hs_complete ) return;
  quic->cb.conn_hs_complete( conn, quic->cb.quic_ctx );
}

static inline void
fd_quic_cb_conn_final( fd_quic_t *      quic,
                       fd_quic_conn_t * conn ) {
  if( !quic->cb.conn_final || !conn->called_conn_new ) return;
  quic->cb.conn_final( conn, quic->cb.quic_ctx );
}

static inline int
fd_quic_cb_stream_rx( fd_quic_t *        quic,
                      fd_quic_conn_t *   conn,
                      ulong              stream_id,
                      ulong              offset,
                      uchar const *      data,
                      ulong              data_sz,
                      int                fin ) {
  quic->metrics.stream_rx_event_cnt++;
  quic->metrics.stream_rx_byte_cnt += data_sz;

  if( !quic->cb.stream_rx ) return FD_QUIC_SUCCESS;
  return quic->cb.stream_rx( conn, stream_id, offset, data, data_sz, fin );
}

static inline void
fd_quic_cb_stream_notify( fd_quic_t *        quic,
                          fd_quic_stream_t * stream,
                          void *             stream_ctx,
                          int                event ) {
  quic->metrics.stream_closed_cnt[ event ]++;
  quic->metrics.stream_active_cnt--;

  if( !quic->cb.stream_notify ) return;
  quic->cb.stream_notify( stream, stream_ctx, event );
}


FD_FN_CONST ulong
fd_quic_reconstruct_pkt_num( ulong pktnum_comp,
                             ulong pktnum_sz,
                             ulong exp_pkt_number );

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
fd_quic_process_quic_packet_v1( fd_quic_t *     quic,
                                fd_quic_pkt_t * pkt,
                                uchar *         cur_ptr,
                                ulong           cur_sz );

ulong
fd_quic_handle_v1_initial( fd_quic_t *               quic,
                           fd_quic_conn_t **         p_conn,
                           fd_quic_pkt_t *           pkt,
                           fd_quic_conn_id_t const * dcid,
                           fd_quic_conn_id_t const * scid,
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

/* fd_quic_lazy_ack_pkt enqueues future acknowledgement for the given
   packet.  The ACK will be sent out at a fd_quic_service call.  The
   delay is determined by the fd_quic_config_t ack_threshold and
   ack_delay settings.   Respects pkt->ack_flag (ACK_FLAG_RQD schedules
   an ACK instantly, ACK_FLAG_CANCEL suppresses the ACK by making this
   function behave like a no-op)  */

int
fd_quic_lazy_ack_pkt( fd_quic_t *           quic,
                      fd_quic_conn_t *      conn,
                      fd_quic_pkt_t const * pkt );

static inline fd_quic_conn_t *
fd_quic_conn_at_idx( fd_quic_state_t * quic_state, ulong idx ) {
  ulong addr = quic_state->conn_base;
  ulong sz   = quic_state->conn_sz;
  return (fd_quic_conn_t*)( addr + idx * sz );
}

/* called with round-trip-time (rtt) and the ack delay (from the spec)
 * to sample the round trip times.
 * Arguments:
 *   conn            The connection to be updated
 *   rtt_ticks       The round trip time in ticks
 *   ack_delay       The ack_delay field supplied by the peer in peer units
 *
 * Updates:
 *   smoothed_rtt    EMA over adjusted rtt
 *   min_rtt         minimum unadjusted rtt over all samples
 *   latest_rtt      the most recent rtt sample */
static inline void
fd_quic_sample_rtt( fd_quic_conn_t * conn, long rtt_ticks, long ack_delay ) {
  /* for convenience */
  fd_quic_conn_rtt_t * rtt = conn->rtt;

  /* ack_delay is in peer units, so scale to put in ticks */
  float ack_delay_ticks = (float)ack_delay * rtt->peer_ack_delay_scale;

  /* bound ack_delay by peer_max_ack_delay */
  ack_delay_ticks = fminf( ack_delay_ticks, rtt->peer_max_ack_delay_ticks );

  /* minrtt is estimated from rtt_ticks without adjusting for ack_delay */
  rtt->min_rtt = fminf( rtt->min_rtt, (float)rtt_ticks );

  /* smoothed_rtt is calculated from adjusted rtt_ticks
       except: ack_delay must not be subtracted if the result would be less than minrtt */
  float adj_rtt = fmaxf( rtt->min_rtt, (float)rtt_ticks - (float)ack_delay_ticks );

  rtt->latest_rtt = adj_rtt;

  /* according to rfc 9002 */
  if( !rtt->is_rtt_valid ) {
    rtt->smoothed_rtt = adj_rtt;
    rtt->var_rtt      = adj_rtt * 0.5f;
    rtt->is_rtt_valid = 1;
  } else {
    rtt->smoothed_rtt = (7.f/8.f) * rtt->smoothed_rtt + (1.f/8.f) * adj_rtt;
    float var_rtt_sample = fabsf( rtt->smoothed_rtt - adj_rtt );
    rtt->var_rtt = (3.f/4.f) * rtt->var_rtt + (1.f/4.f) * var_rtt_sample;

    FD_DEBUG({
      double us_per_tick = 1.0 / (double)conn->quic->config.tick_per_us;
      FD_LOG_NOTICE(( "conn_idx: %u  min_rtt: %f  smoothed_rtt: %f  var_rtt: %f  adj_rtt: %f  rtt_ticks: %f  ack_delay_ticks: %f  diff: %f",
                       (uint)conn->conn_idx,
                       us_per_tick * (double)rtt->min_rtt,
                       us_per_tick * (double)rtt->smoothed_rtt,
                       us_per_tick * (double)rtt->var_rtt,
                       us_per_tick * (double)adj_rtt,
                       us_per_tick * (double)rtt_ticks,
                       us_per_tick * (double)ack_delay_ticks,
                       us_per_tick * ( (double)rtt_ticks - (double)ack_delay_ticks ) ));
    })
  }

}

/* fd_quic_calc_expiry returns the timestamp of the next expiry event. */

static inline ulong
fd_quic_calc_expiry( fd_quic_conn_t * conn, ulong now ) {
  /* Instead of a full implementation of PTO, we're setting an expiry
     time per sent QUIC packet
     This calculates the expiry time according to the PTO spec
     6.2.1. Computing PTO
     When an ack-eliciting packet is transmitted, the sender schedules
     a timer for the PTO period as follows:
     PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay  */

  fd_quic_conn_rtt_t * rtt = conn->rtt;

  ulong duration = (ulong)( rtt->smoothed_rtt
                        + fmaxf( 4.0f * rtt->var_rtt, rtt->sched_granularity_ticks )
                        + rtt->peer_max_ack_delay_ticks );

  FD_DTRACE_PROBE_2( quic_calc_expiry, conn->our_conn_id, duration );

  return now + (ulong)500e6; /* 500ms */
}

uchar *
fd_quic_gen_stream_frames( fd_quic_conn_t *     conn,
                           uchar *              payload_ptr,
                           uchar *              payload_end,
                           fd_quic_pkt_meta_t * pkt_meta,
                           ulong                pkt_number,
                           ulong                now );

void
fd_quic_process_ack_range( fd_quic_conn_t      *      conn,
                           fd_quic_frame_ctx_t *      context,
                           uint                       enc_level,
                           ulong                      largest_ack,
                           ulong                      ack_range,
                           int                        is_largest,
                           ulong                      now,
                           ulong                      ack_delay );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_private_h */
