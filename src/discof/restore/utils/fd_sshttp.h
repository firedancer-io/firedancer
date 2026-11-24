#ifndef HEADER_fd_src_discof_restore_utils_fd_sshttp_h
#define HEADER_fd_src_discof_restore_utils_fd_sshttp_h

struct fd_sshttp_private;
typedef struct fd_sshttp_private fd_sshttp_t;

#include "../../../util/net/fd_net_headers.h"

#include <sys/uio.h>

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshttp_align( void );

FD_FN_CONST ulong
fd_sshttp_footprint( void );

void *
fd_sshttp_new( void * shmem,
               int    epoll_fd );

fd_sshttp_t *
fd_sshttp_join( void * sshttp );

/* fd_sshttp_load_ca_store loads the system CA certificate bundle for
   TLS certificate chain validation.  If no bundle is found, subsequent
   fd_sshttp_init calls with is_https set fail before connecting. */

void
fd_sshttp_load_ca_store( fd_sshttp_t * http );

char const *
fd_sshttp_snapshot_name( fd_sshttp_t const * http );

/* fd_sshttp_content_len returns the length of the response body.  The
   body of a fast boot stream has no length: this is how many bytes of
   it the server had when it answered. */

ulong
fd_sshttp_content_len( fd_sshttp_t const * http );

/* fd_sshttp_stream_caught_up returns 1 once the bytes a fast boot
   stream had when the server answered were all read. */

int
fd_sshttp_stream_caught_up( fd_sshttp_t const * http );

ulong
fd_sshttp_resolved_slot( fd_sshttp_t const * http );

uchar const *
fd_sshttp_resolved_hash( fd_sshttp_t const * http );

/* fd_sshttp_init initializes an sshttp connection to the given server.
   addr is the resolved IP address and port.  hostname is a
   null-terminated string used for the Host header and TLS SNI.  The
   hostname and path are copied; no caller memory is borrowed.
   is_https indicates whether TLS should be used.  path points to the
   URL path of length path_len.  hops is the maximum number of HTTP
   redirects to follow, pass ULONG_MAX to preserve the current hops
   value (e.g. when following a redirect internally).  now is the
   current timestamp.  is_stream marks a fast boot stream request.  A
   nonzero range_start asks the server to resume the stream at that
   byte offset; only a stream resumes.  A redirect to another stream
   reads it from its start.  Returns 0 on success and -1 on
   failure. */

int
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  hostname,
                int           is_https,
                char const *  path,
                ulong         path_len,
                ulong         hops,
                long          now,
                ulong         range_start,
                int           is_stream );

/* fd_sshttp_request asks the server of the last request for path,
   from byte range_start, following redirects.  A redirect to another
   file reads that file from its start.  The connection must be idle. */

int
fd_sshttp_request( fd_sshttp_t * http,
                   long          now,
                   char const *  path,
                   ulong         path_len,
                   ulong         range_start );

void
fd_sshttp_cancel( fd_sshttp_t * http );

/* fd_sshttp_deadline returns the wallclock at which the current step
   times out, or LONG_MAX when idle. */

long
fd_sshttp_deadline( fd_sshttp_t const * http );

#define FD_SSHTTP_ADVANCE_ERROR         (-1) /* the request failed */
#define FD_SSHTTP_ADVANCE_AGAIN         ( 0) /* nothing to report yet */
#define FD_SSHTTP_ADVANCE_DATA          ( 1) /* body bytes in data */
#define FD_SSHTTP_ADVANCE_DONE          ( 2) /* file: the whole body arrived */
#define FD_SSHTTP_ADVANCE_NOT_FOUND     ( 3) /* 404 */

/* fd_sshttp_advance drives the connection.  Body bytes fill iov
   front to back; on ADVANCE_DATA *data_len is the total written.
   Bytes received alongside headers only ever fill iov[0]. */

#define FD_SSHTTP_IOV_MAX (2UL)

/* SO_RCVBUF for download sockets.  Bypasses the net.ipv4.tcp_rmem
   autotuning cap, which is too small for high bandwidth-delay links.
   Clamped by net.core.rmem_max, which the sysctl stage raises. */

#define FD_SSHTTP_SO_RCVBUF (128UL<<20)

/* SO_RCVLOWAT for plaintext body downloads.  The socket reports
   readable (to epoll) only once this many body bytes are queued,
   lowered to the remaining length for the tail of the body, so every
   wake is followed by large reads instead of one per arriving
   segment. */

#define FD_SSHTTP_SO_RCVLOWAT (1UL<<20)

int
fd_sshttp_advance( fd_sshttp_t *        http,
                   struct iovec const * iov,
                   ulong                iov_cnt,
                   ulong *              data_len,
                   int *                downloading,
                   long                 now );

/* fd_sshttp_rx_parked returns 1 if http is downloading a plaintext
   body and its last socket read found nothing queued.  The caller may
   then batch reads by skipping fd_sshttp_advance until its readiness
   notification (epoll) reports the socket readable; up to
   FD_SSHTTP_SO_RCVLOWAT-1 bytes may be queued meanwhile.  Readiness
   covers the end of the body and peer close or error. */

int
fd_sshttp_rx_parked( fd_sshttp_t const * http );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshttp_h */
