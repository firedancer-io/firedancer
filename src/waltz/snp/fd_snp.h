#ifndef HEADER_fd_src_waltz_snp_fd_snp_h
#define HEADER_fd_src_waltz_snp_fd_snp_h

#include "fd_snp_base.h"
#include "fd_snp_proto.h"
#include "fd_snp_private.h"
#include "fd_snp_s0_client.h"
#include "fd_snp_s0_server.h"

/* FD_SNP_API marks public API declarations.  No-op for now. */
#define FD_SNP_API


/* fd_snp_limits_t defines the memory layout of an fd_snp_t object.
   Limits are immutable and valid for the lifetime of an fd_snp_t
   (i.e. outlasts joins, until fd_snp_delete) */

struct __attribute__((aligned(16UL))) fd_snp_limits {
  ulong  conn_cnt;              /* instance-wide, max concurrent conn count */
};
typedef struct fd_snp_limits fd_snp_limits_t;

/* fd_snp_now_t is the clock source used internally by snp for
   scheduling events.  context is an arbitrary pointer earlier provided
   by the caller during config. */

typedef ulong
(*fd_snp_now_t)( void * context );


/* Callback API *******************************************************/

typedef void
(* fd_snp_cb_rx_t)( fd_snp_t      *  snp,
                    snp_net_ctx_t *  sockAddr,
                    uchar const *    data,
                    ulong            data_sz );


typedef void
(* fd_snp_cb_tx_t)( fd_snp_t      *  snp,
                    snp_net_ctx_t *  sockAddr,
                    uchar const *    data,
                    ulong            data_sz );

struct fd_snp_callbacks {
  /* Function pointers to user callbacks */

  void * snp_ctx; /* user-provided context pointer
                      for instance-wide callbacks */

  fd_snp_cb_rx_t                 rx;         /* non-NULL, with stream_ctx */
  fd_snp_cb_tx_t                 tx; /* sends UDP payload, handle rest in callback */

  /* Clock source */
  fd_snp_now_t now;     /* non-NULL */
  void *        now_ctx; /* user-provided context pointer for now_fn calls */

};
typedef struct fd_snp_callbacks fd_snp_callbacks_t;


struct fd_snp {
  ulong magic;   /* ==FD_QUIC_MAGIC */

  fd_snp_limits_t    limits;
  fd_snp_callbacks_t cb;

  fd_snp_s0_client_params_t client_params;
  fd_snp_s0_server_params_t server_params;
  /* ... private variable-length structures follow ... */
};

FD_PROTOTYPES_BEGIN

/* construction API */

FD_SNP_API static FD_FN_CONST inline ulong
fd_snp_align( void ) {
  return 8; /* TODO - reason through and fix later */
}

FD_SNP_API ulong
fd_snp_footprint( fd_snp_limits_t const * limits );

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
fd_snp_send( fd_snp_t * snp,
             snp_net_ctx_t *  dst,
             void const *     data,
             ulong            data_sz);


/* TODO document this */
/* should include IP/UDP headers, not ethernet */
FD_SNP_API void
fd_snp_process_packet( fd_snp_t * snp,
                       const uchar *     data,
                       ulong       data_sz,
                       uint          src_ip,
                       ushort      src_port );

FD_PROTOTYPES_END


#endif
