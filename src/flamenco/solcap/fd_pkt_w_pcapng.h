#ifndef HEADER_fd_src_flamenco_solcap_fd_pkt_w_pcapng_h
#define HEADER_fd_src_flamenco_solcap_fd_pkt_w_pcapng_h

/* fd_pkt_w_pcapng.h provides a packet writer that produces a pcapng
   file. */

#include "fd_pkt_writer.h"
#include <stdio.h>

/* fd_pkt_w_pcapng_t is a packet writer that writes packets to a pcapng
   file on the file system.  Does synchronous blocking writes with
   buffering.

   Uses the following encapsulation:
   - LINKTYPE_NULL (BSD loopback link header)
   - IPv4 header (127.0.0.1->127.0.0.1, no options)
   - UDP (port 30260) */

struct fd_pkt_w_pcapng {
  fd_pkt_writer_t base;

  FILE * file;

  int io_errno;
};

typedef struct fd_pkt_w_pcapng fd_pkt_w_pcapng_t;

FD_PROTOTYPES_BEGIN

/* fd_pkt_w_pcapng_new creates a new pkt_w_pcapng object (pkt_writer
   compatible).  pcapng_fd is a writable file descriptor to which the
   pcapng flow will be appended.  Ownership of pcanpg_fd is transfered
   to the pkt_w_pcapng object.  Wraps the pcapng_fd to a FILE handle
   after the hood.  May return NULL on failure (if fdopen fails), in
   which case pcapng_fd is closed.

   fd_pkt_writer_post enqueues a packet for writing (may not immediately
   write out the data).

   fd_pkt_writer_flush writes out all enqueued packets to file (does not
   fsync).

   fd_pkt_writer_fini destroys pkt_w_pcapng object, the underlying FILE
   handle, adn closes the pcapng_fd file descriptor. */

fd_pkt_writer_t *
fd_pkt_w_pcapng_new( fd_pkt_w_pcapng_t * w,
                     int                 pcapng_fd,
                     uchar *             dcache,
                     ulong               mtu );

int
fd_pkt_w_pcapng_write( FILE *        file,
                       uchar const * buf,
                       ulong         sz,
                       long          ts );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_solcap_fd_pkt_w_pcapng_h */
