#ifndef HEADER_fd_src_flamenco_solcap_fd_pkt_w_tango_h
#define HEADER_fd_src_flamenco_solcap_fd_pkt_w_tango_h

/* fd_pkt_w_tango.h provides a packet writer that publishes to shared
   memory queues. */

#include "fd_pkt_writer.h"
#include "../../tango/fd_tango_base.h"

/* fd_pkt_w_tango_t is a packet writer that publishes packets to an
   fd_tango SPMC queue (mcache/dcache pair).  Currently does not support
   backpressure.

   Fragment descriptor format:
   - sig[0..8]:   event type
   - sig[8..32]:  event size
   - sig[32..64]: unused
   - chunk:       compressed pointer to Protobuf message
   - sz:          unused
   - ctl:         unused
   - tsorig:      unused
   - tspub:       unused */

struct fd_pkt_w_tango {

  fd_pkt_writer_t base;

  fd_frag_meta_t * out_mcache;
  ulong            out_depth;
  ulong            out_seq;

};

typedef struct fd_pkt_w_tango fd_pkt_w_tango_t;

FD_PROTOTYPES_BEGIN

/* fd_pkt_w_tango_new creates a new pkt_w_tango object (pkt_writer
   compatible).

   fd_pkt_writer_post immediately publishes an event to mcache.

   fd_pkt_writer_flush updates mcache->seq[0].

   fd_pkt_writer_fini is no-op (nothing to deinitialize). */

fd_pkt_writer_t *
fd_pkt_w_tango_new( fd_pkt_w_tango_t * w,
                    fd_frag_meta_t *   mcache,
                    uchar *            dcache,
                    void *             base,
                    ulong              mtu );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_solcap_fd_pkt_w_tango_h */
