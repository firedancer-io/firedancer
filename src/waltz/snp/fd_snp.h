#ifndef HEADER_fd_src_waltz_snp_fd_snp_h
#define HEADER_fd_src_waltz_snp_fd_snp_h

#include "fd_snp_common.h"
#include "fd_snp_proto.h"

/* FD_SNP_API marks public API declarations.  No-op for now. */
#define FD_SNP_API

/* fd_snp_limits_t defines the memory layout of an fd_snp_t object.
   Limits are immutable and valid for the lifetime of an fd_snp_t
   (i.e. outlasts joins, until fd_snp_delete) */

struct __attribute__((aligned(16UL))) fd_snp_limits {
  ulong conn_cnt;              /* instance-wide, max concurrent conn count      */
  // ulong handshake_cnt;         /* instance-wide, max concurrent handshake count */
  // ulong cached_pkts_cnt;       /* instance-wide, max cached packets count */
  // ulong  log_depth;             /* instance-wide, depth of shm log cache         */

  // ulong  conn_id_cnt;           /* per-conn, max conn ID count (min 4UL)         */
  // ulong  inflight_pkt_cnt;      /* per-conn, max inflight packet count           */
};
typedef struct fd_snp_limits fd_snp_limits_t;

struct __attribute__((aligned(16UL))) fd_snp_layout {
  ulong meta_sz;             /* size of this struct */
  ulong conn_pool_off;       /* offset of connections pool mem region */
  ulong conn_map_off;        /* offset of connections map mem region */
  ulong pkt_pool_off;        /* offset of packets pool mem region */
  ulong last_pkt_pool_off;   /* offset of last packets pool mem region */
  // ulong hs_pool_off;      /* offset of the handshake pool     */
  // ulong stream_pool_off;  /* offset of the stream pool        */
  // ulong svc_timers_off;   /* offset of the service timers     */
};
typedef struct fd_snp_layout fd_snp_layout_t;

// struct __attribute__((aligned(16UL))) fd_snp_config {
//   double tick_per_us;  /* tick_per_us: clock ticks per microsecond */
//   long   keep_alive_ms;
//   long   handshake_retry_ms;

//   /* identity pubkey */
//   uchar identity[ SNP_ED25519_KEY_SZ ];

//   /* random AES-128 key to encrypt state (to avoid storing state) */
//   uchar state_enc_key[ SNP_STATE_KEY_SZ ];
// };
// typedef struct fd_snp_config fd_snp_config_t;

/* Callback API *******************************************************/

/* CALLBACKS */

/* send/tx callback.
   This is invoked to send the packet over the wire. */
typedef int
( * fd_snp_cb_tx_t )( void const *         ctx,          /* callback context */
                      uchar const *        packet,       /* packet to send */
                      ulong                packet_sz,    /* size of packet to send */
                      fd_snp_meta_t        meta );       /* connection metadata */

/* recv/rx callback.
   This is invoked for packets with app payload, to dispatch them to the
   proper instance of fd_snp_app. */
typedef int
( * fd_snp_cb_rx_t )( void const *         ctx,          /* callback context */
                      uchar const *        packet,       /* packet to send */
                      ulong                packet_sz,    /* size of packet to send */
                      fd_snp_meta_t        meta );       /* connection metadata */

/* sign callback.
   This is invoked to sign payload during handshake. */
typedef int
( * fd_snp_cb_sign_t )( void const *       ctx,          /* callback context */
                        ulong              session_id,   /* connection session id */
                        uchar const        to_sign[ FD_SNP_TO_SIGN_SZ ] ); /* payload to sign */

struct fd_snp_callbacks {
  /* Function pointers to user callbacks */
  void *           ctx;
  fd_snp_cb_tx_t   tx;
  fd_snp_cb_rx_t   rx;
  fd_snp_cb_sign_t sign;
};
typedef struct fd_snp_callbacks fd_snp_callbacks_t;

struct fd_snp_applications {
  ushort            port;
  ushort            net_id;
  fd_ip4_udp_hdrs_t net_hdr[1];
  uint              multicast_ip;
  fd_ip4_udp_hdrs_t multicast_net_hdr[1];
};
typedef struct fd_snp_applications fd_snp_applications_t;

struct FD_SNP_ALIGNED fd_snp {
  ulong magic;   /* ==FD_QUIC_MAGIC */

  fd_snp_config_t    config;
  fd_snp_layout_t    layout;
  fd_snp_limits_t    limits;
  fd_snp_callbacks_t cb;

  fd_snp_applications_t apps[8];
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
};
typedef struct fd_snp fd_snp_t;

FD_PROTOTYPES_BEGIN

/* construction API */

FD_SNP_API static FD_FN_CONST inline ulong
fd_snp_align( void ) {
  return FD_SNP_ALIGN;
}

FD_SNP_API ulong
fd_snp_footprint( fd_snp_limits_t const * limits );

ulong
fd_snp_footprint_ext( fd_snp_limits_t const * limits,
                      fd_snp_layout_t *       layout );

/* TODO document */
FD_SNP_API void *
fd_snp_new( void *                   mem,
            fd_snp_limits_t const * limits );

/* fd_snp_join joins the caller to the fd_snp.  shsnp points to the
first byte of the memory region backing the QUIC in the caller's
address space.

Returns a pointer in the local address space to the public fd_snp_t
region on success (do not assume this to be just a cast of shsnp)
and NULL on failure (logs details).  Reasons for failure are that
shsnp is obviously not a pointer to a correctly formatted QUIC
object.  Every successful join should have a matching leave.  The
lifetime of the join is until the matching leave or the thread group
is terminated. */

FD_SNP_API fd_snp_t *
fd_snp_join( void * shsnp );


/* Initialization *****************************************************/

/* fd_snp_init initializes the SNP such that it is ready to serve.
   permits the calling thread exclusive access during which no other
   thread may write to the SNP.  Exclusive rights get released when the
   thread exits or calls fd_snp_fini.

   Requires valid configuration and external objects (callbacks).
   Returns given snp on success and NULL on failure (logs details).
   Performs various heap allocations and file system accesses such
   reading certs.  Reasons for failure include invalid config or
   fd_tls error. */

FD_SNP_API fd_snp_t *
fd_snp_init( fd_snp_t * snp );

/* fd_snp_fini releases exclusive access over a SNP.  Zero-initializes
   references to external objects (aio, callbacks).  Frees any heap
   allocs made by fd_snp_init.  Returns snp. */

FD_SNP_API fd_snp_t *
fd_snp_fini( fd_snp_t * snp );


/* Service API ********************************************************/

/* AMAN TODO - document this, and add it to the shred client */
FD_SNP_API int
fd_snp_service_timers( fd_snp_t * snp );


/* fd_snp_send 'sends' data_sz of data to dst.
  it actually encodes into out_buf wire-ready
  TODO - change this to actually track the lddr and send
  but that's a later problem :)
  It should add all internet headers (eth, IP, UDP)
  TODO - make this templated
   returns
    number of bytes encoded if success
    <0   one of FD_SNP_SEND_ERR_{INVAL_STREAM,INVAL_CONN,AGAIN} */

FD_SNP_API int
fd_snp_send( fd_snp_t *    snp,
             uchar *       packet,
             ulong         packet_sz,
             fd_snp_meta_t meta );


/* TODO document this */
/* should include IP/UDP headers, not ethernet */
FD_SNP_API int
fd_snp_process_packet( fd_snp_t * snp,
                       uchar *    packet,
                       ulong      packet_sz );

FD_SNP_API int
fd_snp_process_signature( fd_snp_t *  snp,
                          ulong       session_id,
                          uchar const signature[ 64 ] );

FD_SNP_API int
fd_snp_housekeeping( fd_snp_t * snp );

FD_SNP_API int
fd_snp_set_identity( fd_snp_t *    snp,
                     uchar const * new_identity );

int
fd_snp_conn_delete( fd_snp_t * snp,
                    fd_snp_conn_t * conn );

FD_PROTOTYPES_END

#endif
