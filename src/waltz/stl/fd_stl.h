#ifndef HEADER_fd_src_waltz_stl_fd_stl_h
#define HEADER_fd_src_waltz_stl_fd_stl_h

#include "fd_stl_base.h"
#include "fd_stl_proto.h"
#include "fd_stl_private.h"
#include "fd_stl_s0_client.h"
#include "fd_stl_s0_server.h"

/* FD_STL_API marks public API declarations.  No-op for now. */
#define FD_STL_API


/* fd_stl_limits_t defines the memory layout of an fd_stl_t object.
   Limits are immutable and valid for the lifetime of an fd_stl_t
   (i.e. outlasts joins, until fd_stl_delete) */

struct __attribute__((aligned(16UL))) fd_stl_limits {
  ulong  conn_cnt;              /* instance-wide, max concurrent conn count */
};
typedef struct fd_stl_limits fd_stl_limits_t;

/* fd_stl_now_t is the clock source used internally by stl for
   scheduling events.  context is an arbitrary pointer earlier provided
   by the caller during config. */

typedef ulong
(*fd_stl_now_t)( void * context );


/* Callback API *******************************************************/

typedef void
(* fd_stl_cb_rx_t)( fd_stl_t      *  stl,
                    stl_net_ctx_t *  sockAddr,
                    uchar const *    data,
                    ulong            data_sz );


typedef void
(* fd_stl_cb_tx_t)( fd_stl_t      *  stl,
                    stl_net_ctx_t *  sockAddr,
                    uchar const *    data,
                    ulong            data_sz );

struct fd_stl_callbacks {
  /* Function pointers to user callbacks */

  void * stl_ctx; /* user-provided context pointer
                      for instance-wide callbacks */

  fd_stl_cb_rx_t                 rx;         /* non-NULL, with stream_ctx */
  fd_stl_cb_tx_t                 tx; /* sends UDP payload, handle rest in callback */

  /* Clock source */
  fd_stl_now_t now;     /* non-NULL */
  void *        now_ctx; /* user-provided context pointer for now_fn calls */

};
typedef struct fd_stl_callbacks fd_stl_callbacks_t;


struct fd_stl {
  ulong magic;   /* ==FD_QUIC_MAGIC */

  fd_stl_limits_t    limits;
  fd_stl_callbacks_t cb;

  fd_stl_s0_client_params_t client_params;
  fd_stl_s0_server_params_t server_params;
  /* ... private variable-length structures follow ... */
};

FD_PROTOTYPES_BEGIN

/* construction API */

FD_STL_API static FD_FN_CONST inline ulong
fd_stl_align( void ) {
  return 8; /* TODO - reason through and fix later */
}

FD_STL_API ulong
fd_stl_footprint( fd_stl_limits_t const * limits );

/* TODO document */
FD_STL_API void *
fd_stl_new( void *                   mem,
            fd_stl_limits_t const * limits );

/* fd_stl_join joins the caller to the fd_stl.  shstl points to the
first byte of the memory region backing the QUIC in the caller's
address space.

Returns a pointer in the local address space to the public fd_stl_t
region on success (do not assume this to be just a cast of shstl)
and NULL on failure (logs details).  Reasons for failure are that
shstl is obviously not a pointer to a correctly formatted QUIC
object.  Every successful join should have a matching leave.  The
lifetime of the join is until the matching leave or the thread group
is terminated. */

FD_STL_API fd_stl_t *
fd_stl_join( void * shstl );


/* Initialization *****************************************************/

/* fd_stl_init initializes the STL such that it is ready to serve.
   permits the calling thread exclusive access during which no other
   thread may write to the STL.  Exclusive rights get released when the
   thread exits or calls fd_stl_fini.

   Requires valid configuration and external objects (callbacks).
   Returns given stl on success and NULL on failure (logs details).
   Performs various heap allocations and file system accesses such
   reading certs.  Reasons for failure include invalid config or
   fd_tls error. */

FD_STL_API fd_stl_t *
fd_stl_init( fd_stl_t * stl );

/* fd_stl_fini releases exclusive access over a STL.  Zero-initializes
   references to external objects (aio, callbacks).  Frees any heap
   allocs made by fd_stl_init.  Returns stl. */

FD_STL_API fd_stl_t *
fd_stl_fini( fd_stl_t * stl );


/* Service API ********************************************************/

/* AMAN TODO - document this, and add it to the shred client */
FD_STL_API int
fd_stl_service_timers( fd_stl_t * stl );


/* fd_stl_send 'sends' data_sz of data to dst.
  it actually encodes into out_buf wire-ready
  TODO - change this to actually track the lddr and send
  but that's a later problem :)
  It should add all internet headers (eth, IP, UDP)
  TODO - make this templated
   returns
    number of bytes encoded if success
    <0   one of FD_STL_SEND_ERR_{INVAL_STREAM,INVAL_CONN,AGAIN} */

FD_STL_API int
fd_stl_send( fd_stl_t * stl,
             stl_net_ctx_t *  dst,
             void const *     data,
             ulong            data_sz);


/* TODO document this */
/* should include IP/UDP headers, not ethernet */
FD_STL_API void
fd_stl_process_packet( fd_stl_t * stl,
                       const uchar *     data,
                       ulong       data_sz,
                       uint          src_ip,
                       ushort      src_port );

FD_PROTOTYPES_END


#endif
