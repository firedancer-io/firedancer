#ifndef HEADER_fd_src_waltz_snp_fd_snp_h
#define HEADER_fd_src_waltz_snp_fd_snp_h

#include "fd_snp_common.h"
#include "fd_snp_proto.h"
#include "../../util/net/fd_net_headers.h"

/* fd_snp_limits_t defines the limits used to allocate
   memory for the SNP instance. */
struct __attribute__((aligned(16UL))) fd_snp_limits {
  ulong peer_cnt;            /* instance-wide, max peer count */
};
typedef struct fd_snp_limits fd_snp_limits_t;

/* fd_snp_layout_t defines the memory layout of an fd_snp_t object.
   Limits are immutable and valid for the lifetime of an fd_snp_t
   (i.e. outlasts joins, until fd_snp_delete) */
struct __attribute__((aligned(16UL))) fd_snp_layout {
  ulong meta_sz;             /* size of this struct */
  ulong conn_pool_off;       /* offset of connections pool mem region */
  ulong conn_map_off;        /* offset of connections map mem region */
  ulong pkt_pool_off;        /* offset of packets pool mem region */
  ulong last_pkt_pool_off;   /* offset of last packets pool mem region */
  ulong dest_meta_map_off_a; /* offset of destinations meta map A mem region */
  ulong dest_meta_map_off_b; /* offset of destinations meta map B mem region */
};
typedef struct fd_snp_layout fd_snp_layout_t;

/* Callback API *****************************************************/

/* CALLBACKS */

/* send/tx callback is invoked to send the packet over the wire. */
typedef int
( * fd_snp_cb_tx_t )( void const *         ctx,          /* callback context */
                      uchar const *        packet,       /* packet to send */
                      ulong                packet_sz,    /* size of packet to send */
                      fd_snp_meta_t        meta );       /* connection metadata */

/* recv/rx callback is invoked for packets with app payload, to
   dispatch them to the proper instance of fd_snp_app. */
typedef int
( * fd_snp_cb_rx_t )( void const *         ctx,          /* callback context */
                      uchar const *        packet,       /* packet to dispatch */
                      ulong                packet_sz,    /* size of packet to dispatch */
                      fd_snp_meta_t        meta );       /* connection metadata */

/* sign callback is invoked to sign payload during handshake. */
typedef int
( * fd_snp_cb_sign_t )( void const *       ctx,          /* callback context */
                        ulong              session_id,   /* connection session id */
                        uchar const        to_sign[ FD_SNP_TO_SIGN_SZ ] ); /* payload to sign */

/* fd_snp_callbacks_t defines the callbacks used by the SNP instance. */
struct fd_snp_callbacks {
  /* Function pointers to user callbacks */
  void *           ctx;
  fd_snp_cb_tx_t   tx;
  fd_snp_cb_rx_t   rx;
  fd_snp_cb_sign_t sign;
};
typedef struct fd_snp_callbacks fd_snp_callbacks_t;

/* fd_snp_applications_t defines the applications supported by the SNP instance. */
struct fd_snp_applications {
  ushort            port;
  ushort            net_id;
  fd_ip4_udp_hdrs_t net_hdr[1];
  uint              multicast_ip;
  fd_ip4_udp_hdrs_t multicast_net_hdr[1];
};
typedef struct fd_snp_applications fd_snp_applications_t;

/* fd_snp_dest_meta_t defines the metadata for a destination peer. */
struct fd_snp_dest_meta {
  long   snp_handshake_tstamp;
  uint   update_idx;
  uint   ip4_addr;
  ushort udp_port;
  uchar  snp_available;
  uchar  snp_enabled;
  uchar  snp_enforced;
  uchar  reserved[3];
};
typedef struct fd_snp_dest_meta fd_snp_dest_meta_t;

/* fd_snp_dest_meta_map_t defines the map of destination metadata. */
struct __attribute__((aligned(32))) fd_snp_dest_meta_map {
  ulong              key;
  fd_snp_dest_meta_t val;
};
typedef struct fd_snp_dest_meta_map fd_snp_dest_meta_map_t;

#define MAP_NAME        fd_snp_dest_meta_map
#define MAP_T           fd_snp_dest_meta_map_t
#define MAP_MEMOIZE     0
#define MAP_HASH_T      ulong
#define MAP_KEY_HASH(k) (k)
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_snp_metrics_t defines the metrics for the SNP instance. */
struct fd_snp_metrics {
  ulong   dest_meta_cnt;
  ulong   dest_meta_snp_available_cnt;
  ulong   dest_meta_snp_enabled_cnt;

  ulong   conn_cur_total;                /* pool cnt. */
  ulong   conn_cur_established;          /* current number of active connections. */
  ulong   conn_acc_total;                /* incr every time we create a connections. */
  ulong   conn_acc_established;          /* incr every time we complete a handshake. */
  ulong   conn_acc_dropped;              /* incr every time we delete a connection. */
  ulong   conn_acc_dropped_handshake;    /* incr every time we delete a handshake connection. */
  ulong   conn_acc_dropped_established;  /* incr every time we delete an established connection. */
  ulong   conn_acc_dropped_set_identity; /* incr every time we delete a connection due to set identity. */

  ulong   tx_bytes_via_udp_to_snp_avail_cnt;
  ulong   tx_pkts_via_udp_to_snp_avail_cnt;

  ulong   tx_bytes_via_udp_cnt;
  ulong   tx_bytes_via_snp_cnt;
  ulong   tx_pkts_via_udp_cnt;
  ulong   tx_pkts_via_snp_cnt;
  ulong   tx_pkts_dropped_no_credits_cnt;

  ulong   rx_bytes_cnt;
  ulong   rx_bytes_via_udp_cnt;
  ulong   rx_bytes_via_snp_cnt;
  ulong   rx_pkts_cnt;
  ulong   rx_pkts_via_udp_cnt;
  ulong   rx_pkts_via_snp_cnt;
  ulong   rx_pkts_dropped_no_credits_cnt;
};
typedef struct fd_snp_metrics fd_snp_metrics_t;

/* fd_snp_t defines the SNP instance. */
struct FD_SNP_ALIGNED fd_snp {
  ulong magic;   /* ==FD_SNP_MAGIC */

  fd_snp_config_t    config;
  fd_snp_layout_t    layout;
  fd_snp_limits_t    limits;
  fd_snp_callbacks_t cb;

  fd_snp_applications_t apps[FD_SNP_APPS_CNT_MAX];
  ulong                 apps_cnt;

  struct {
    ulong               ip4;
    ushort              net_id;
    fd_ip4_udp_hdrs_t   net_hdr[1];
  }                     multicast;

  fd_snp_conn_t *       conn_pool;
  fd_snp_conn_map_t *   conn_map;
  fd_snp_pkt_t *        pkt_pool;
  fd_snp_pkt_t *        last_pkt_pool;

  /* Support negative values to simplify arithmetic operations. */
  long flow_cred_total;
  long flow_cred_taken;
  long flow_cred_alloc;

  fd_snp_dest_meta_map_t * dest_meta_map_a;
  fd_snp_dest_meta_map_t * dest_meta_map_b;
  fd_snp_dest_meta_map_t * dest_meta_map;
  uint                     dest_meta_update_idx;
  long                     dest_meta_next_update_ts;

  fd_rng_t      rng_mem[ 1 ];
  fd_rng_t *    rng;

  /* Metrics.
     We currently duplicate the metrics for all vs enforced connections.
     We want to monitor how SNP behaves when enforced, before we enforce it
     for everybody. */
  fd_snp_metrics_t metrics_all[1];
  fd_snp_metrics_t metrics_enf[1];
};
typedef struct fd_snp fd_snp_t;

FD_PROTOTYPES_BEGIN

/* construction API */

static FD_FN_CONST inline ulong
fd_snp_align( void ) {
  return FD_SNP_ALIGN;
}

/* fd_snp_footprint returns the footprint of the fd_snp_t structure. */
ulong
fd_snp_footprint( fd_snp_limits_t const * limits );

/* fd_snp_new formats an unused memory region for use as a SNP.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */
void *
fd_snp_new( void *                   mem,
            fd_snp_limits_t const * limits );

/* fd_snp_join joins the caller to the fd_snp.  shsnp points to the
   first byte of the memory region backing the SNP in the caller's
   address space. */
fd_snp_t *
fd_snp_join( void * shsnp );

/* fd_snp_init initializes the SNP such that it is ready to serve.
   permits the calling thread exclusive access during which no other
   thread may write to the SNP.  Exclusive rights get released when
   the thread exits or calls fd_snp_fini.

   Requires valid configuration and external objects (callbacks).
   Returns given snp on success and NULL on failure (logs details).
   Performs various heap allocations and file system accesses such
   reading certs.  Reasons for failure include invalid config or
   fd_tls error. */
fd_snp_t *
fd_snp_init( fd_snp_t * snp );

/* fd_snp_fini releases exclusive access over a SNP.  Zero-initializes
   references to external objects (aio, callbacks).  Frees any heap
   allocs made by fd_snp_init.  Returns snp. */
fd_snp_t *
fd_snp_fini( fd_snp_t * snp );

/* Service API */

/* fd_snp_send prepares a packet for sending and invokes the send callback.
   It returns a negative value on error (packet dropped), and a non-negative
   value on success (typically the packet size, but the return value is
   controlled by the callback). */
int
fd_snp_send( fd_snp_t *    snp,
             uchar *       packet,
             ulong         packet_sz,
             fd_snp_meta_t meta );

/* fd_snp_process_packet processes an incoming packet received from
   the network.
   Depending on the packet, it invokes one of the registered callbacks:
   - receive callback, if the packet contains a payload for an application
   - send callback, if the packet requires sending a new packet in response
   - sign callback, if the packet requires signing during handshake
   It returns a negative value on error (packet dropped), and a non-negative
   value on success (typically the packet size, but the return value is
   controlled by the callback). */
int
fd_snp_process_packet( fd_snp_t * snp,
                       uchar *    packet,
                       ulong      packet_sz );

/* fd_snp_process_signature processes a signature received asynchronously.
   It invokes the send callback to send the signed packet to the peer.
   It returns a negative value on error (signature dropped), and a non-negative
   value on success (typically the packet size, but the return value is
   controlled by the callback). */
int
fd_snp_process_signature( fd_snp_t *  snp,
                          ulong       session_id,
                          uchar const signature[ 64 ] );

/* fd_snp_housekeeping performs housekeeping tasks, such as:
   - checking for and removing expired connections
   - implementing keep-alive logic
   - implementing retry logic during handshakes
   This function is expected to be called periodically by the snp tile.
   It invokes the send callback to send any necessary packet.
   The current implementation checks and potentially sends a packet
   for every existing connection. */
void
fd_snp_housekeeping( fd_snp_t * snp );

/* fd_snp_set_identity implements the logic to respond to a set identity event.
   Currently, it deletes all connections. While this may seem a bit extreme and
   in future we may want to gracefully close connections, this is done so that
   we avoid any unnecessary assumptions in the SNP state machine. */
void
fd_snp_set_identity( fd_snp_t *    snp,
                     uchar const * new_identity );


static inline ulong
fd_snp_dest_meta_map_key_from_parts( uint   ip4_addr,
                                     ushort udp_port ) {
  return fd_snp_peer_addr_from_parts( ip4_addr, udp_port );
}

static inline ulong
fd_snp_dest_meta_map_key_from_conn( fd_snp_conn_t * conn ) {
  return conn->peer_addr;
}

FD_PROTOTYPES_END

#endif
