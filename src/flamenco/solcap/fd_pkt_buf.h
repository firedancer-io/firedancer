#ifndef HEADER_fd_src_flamenco_solcap_fd_pkt_buf_h
#define HEADER_fd_src_flamenco_solcap_fd_pkt_buf_h

/* fd_pkt_buf.h provides a single-threaded SPSC deque for packet I/O.
   It is a simpler version of fd_pkt_tango.

   This is primarily a convenience API provided for testing.  Typically,
   this API is used to test solcap itself, by running some runtime
   component with mock inputs.  The test would then capture and check
   the generated solcap messages. */

#include "fd_pkt_w_tango.h"
#include "../../ballet/pb/fd_pb_less.h"

struct fd_pkt_buf {

  fd_pkt_w_tango_t writer;
  fd_frag_meta_t * mcache;
  uchar *          dcache;
  ulong            depth;

  fd_frag_meta_t * tail_frag;
  ulong            tail_seq;

  /* ... mcache memory region follows ... */

  /* ... dcache memory region follows ... */

};

typedef struct fd_pkt_buf fd_pkt_buf_t;

FD_PROTOTYPES_BEGIN

/* fd_pkt_buf_{align,footprint,new,delete} are used to construct and
   destroy pkt_buf objects. */

ulong
fd_pkt_buf_align( void );

ulong
fd_pkt_buf_footprint( ulong depth,
                      ulong mtu );

fd_pkt_buf_t *
fd_pkt_buf_new( void * mem,
                ulong  depth,
                ulong  mtu );

void *
fd_pkt_buf_delete( fd_pkt_buf_t * buf );

/* fd_pkt_buf_writer implements the pkt_writer interface. */

static inline fd_pkt_writer_t *
fd_pkt_buf_writer( fd_pkt_buf_t * buf ) {
  return &buf->writer.base;
}

/* Read API ***********************************************************/

/* fd_pkt_buf_msg returns a pointer to the payload of the current
   packet. */

static inline uchar const *
fd_pkt_buf_msg( fd_pkt_buf_t const * buf ) {
  return fd_chunk_to_laddr_const( buf->dcache, buf->tail_frag->chunk );
}

/* fd_pkt_buf_msg_type returns the message type of the current packet. */

static inline uint
fd_pkt_buf_msg_type( fd_pkt_buf_t * buf ) {
  return buf->tail_frag->sig & 0xff;
}

/* fd_pkt_buf_msg_sz returns the size of the payload of the current
   packet. */

static inline ulong
fd_pkt_buf_msg_sz( fd_pkt_buf_t * buf ) {
  return (buf->tail_frag->sig >> 8) & 0xffffff;
}

/* fd_pkt_buf_next attempts to advance from the current packet to the
   next packet.  Returns 0 if there are no new packets, 1 if it
   advanced, 2 if it advanced but packets were dropped.  All references
   to the current packet must be dropped before calling this API. */

int
fd_pkt_buf_next( fd_pkt_buf_t * buf );

/* fd_pkt_buf_pb parses the current packet as Protobuf. */

fd_pb_less_t *
fd_pkt_buf_pb( fd_pkt_buf_t * buf,
               void *         scratch,
               ulong          scratch_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_solcap_fd_pkt_buf_h */