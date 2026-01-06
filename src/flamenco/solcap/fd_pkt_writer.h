#ifndef HEADER_fd_src_flamenco_solcap_fd_pkt_writer_h
#define HEADER_fd_src_flamenco_solcap_fd_pkt_writer_h

#include "../../util/fd_util_base.h"
#include "../../tango/dcache/fd_dcache.h"

/* Virtual function table for solcap packet writer backends. */

struct fd_pkt_writer_vt {

  void
  (* fini)( void * self );

  void
  (* post)( void * self,
            ulong  sz,
            ulong  msg_type );  /* in [0,256) */

  void
  (* flush)( void * self );

};

typedef struct fd_pkt_writer_vt fd_pkt_writer_vt_t;

/* Base class for solcap packet writers. */

struct fd_pkt_writer {

  fd_pkt_writer_vt_t const * vt;

  ulong mtu;
  ulong quota;

  /* dcache producer */
  void * base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;

};

typedef struct fd_pkt_writer fd_pkt_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_pkt_writer_fini destroys the packet writer object.  See subclass
   documentation for backend-specific behavior. */

static inline void
fd_pkt_writer_fini( fd_pkt_writer_t * w ) {
  w->vt->fini( w );
}

/* fd_pkt_writer_alloc returns a new MTU-size frame for writing
   (infallible).  The user can then either write data into the frame and
   submit it for sending using fd_pkt_writer_post, or discard it by
   calling fd_pkt_writer_alloc again. */

static inline uchar *
fd_pkt_writer_alloc( fd_pkt_writer_t * w ) {
  return fd_chunk_to_laddr( w->base, w->chunk );
}

/* fd_pkt_writer_post enqueues the most recently allocated buffer for
   writing.  The first sz bytes of the buffer contain the message to be
   sent.  The backend may defer the write, see fd_pkt_writer_flush.
   sig is an arbitrary packet type identifier. */

static inline void
fd_pkt_writer_post( fd_pkt_writer_t * w,
                    ulong             sz,
                    ulong             msg_type ) {  /* in [0,256) */
  ulong chunk = w->chunk;
  w->vt->post( w, sz, msg_type );
  w->chunk = fd_dcache_compact_next( chunk, sz, w->chunk0, w->wmark );
}

/* fd_pkt_writer_flush flushes all previously posted writes. */

static inline void
fd_pkt_writer_flush( fd_pkt_writer_t * w ) {
  w->vt->flush( w );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_solcap_fd_pkt_writer_h */
