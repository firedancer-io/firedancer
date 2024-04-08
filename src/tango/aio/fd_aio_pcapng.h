#ifndef HEADER_fd_src_tango_aio_fd_aio_pcapng_h
#define HEADER_fd_src_tango_aio_fd_aio_pcapng_h

#include "fd_aio.h"

/* fd_aio_pcapng implements a MitM aio that sits transparently between a
   sender and receiver while capturing all packets to a file.

   Multiple writers may be joined to the same pcapng stream on the same
   thread, though sharing a pcapng across threads is unsupported.  (One
   could still achieve multi-thread support by buffering all completed
   writes to local memory-backed virtual files per thread and then
   periodically flushing the records using atomic write() syscalls)

   Capture happens unidirectionally -- for duplex create a pair (one for
   RX, one for TX) (Refer to the above re safety of sharing a file
   descriptor) */

struct fd_aio_pcapng {
  fd_aio_t         local;  /* abstract base class */
  fd_aio_t const * dst;    /* aio in local address space */
  void *           pcapng; /* stream object (typically FILE) */
};
typedef struct fd_aio_pcapng fd_aio_pcapng_t;

#define FD_AIO_PCAPNG_ALIGN     (alignof(fd_aio_pcapng_t))
#define FD_AIO_PCAPNG_FOOTPRINT (sizeof (fd_aio_pcapng_t))

FD_PROTOTYPES_BEGIN

/* fd_aio_pcapng_start starts a new PCAPNG section (SHB) and defines a
   single interface (IDB) on the given PCAPNG stream handle (typically
   FILE). This is optional if the caller has already created such an
   SHB/IDB pair.  Returns 1 on success. On failure, returns 0 and sets
   errno.  Stream state is undefined on failure. */

ulong
fd_aio_pcapng_start( void * pcapng );


/* fd_aio_pcapng_join formats the memory region at mitm for use as an
   fd_aio_pcapng_t (with matching size and alignment requirements).
   Returns mitm configured to forward traffic to dst and log traffic
   passing through to stream handle pcapng (typically FILE).
   pcapng must have valid SHB and IDB headers at this point
   (fd_aio_pcapng_start creates such). */

fd_aio_pcapng_t *
fd_aio_pcapng_join( void *           mitm,
                    fd_aio_t const * dst,
                    void *           pcapng );

/* fd_aio_pcapng_leave leaves the current join to the mitm object.
   Caller should first disconnect all other objects configured to send
   to the aio provided by this mitm. */

void *
fd_aio_pcapng_leave( fd_aio_pcapng_t * mitm );

/* fd_aio_pcapng_get_aio returns the fd_aio base class of this
   fd_aio_pcapng_join.  Valid for lifetime of join.  Each packet sent
   to this aio will be written to pcapng.  If pcapng writes fail, will
   continue to forward packets and log warnings.  Packets written refer
   to the default interface in the current section, i.e. the first IDB. */

FD_FN_CONST fd_aio_t const *
fd_aio_pcapng_get_aio( fd_aio_pcapng_t const * mitm );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_aio_fd_aio_pcapng_h */
