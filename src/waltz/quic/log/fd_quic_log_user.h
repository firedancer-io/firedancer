#ifndef HEADER_fd_src_waltz_quic_fd_quic_log_user_h
#define HEADER_fd_src_waltz_quic_fd_quic_log_user_h

/* fd_quic_log_user.h defines an ABI for extracting high frequency logs
   from an fd_quic instance.

   This header does not provide APIs to write logs.  For those, look in
   fd_quic_log_internal.h (as the name implies, currently not stable). */

#include "fd_quic_log.h"
#include "../../../tango/mcache/fd_mcache.h"

/* FIXME: Consider custom ring buffer layout instead of using mainline
          fd_frag_meta_t?  Would allow moving most log information into
          the metadata ring, obsoleting the need for a separate data
          cache ring. */

/* fd_quic_log_rx_t contains parameters of a consumer-side join to a
   quic_log interface. */

struct fd_quic_log_rx {
  fd_frag_meta_t const * mcache;
  ulong const *          mcache_seq;
  void *                 base;
  ulong                  data_lo_laddr;
  ulong                  data_hi_laddr;
  ulong                  seq;
  ulong                  depth;
};

typedef struct fd_quic_log_rx fd_quic_log_rx_t;

/* FD_QUIC_LOG_ALIGN describes the expected alignment of a quic_log. */

#define FD_QUIC_LOG_ALIGN (64UL)

/* FD_QUIC_LOG_MAGIC is used to signal the layout of shared memory
   region of a quic_log. */

#define FD_QUIC_LOG_MAGIC (0x9002c4662f7e58b5UL)

FD_PROTOTYPES_BEGIN

/* fd_quic_log_rx_join joins the caller to a quic_log as a consumer.
   shmlog points to a quic_log_abi object in the local address space.
   On success, fills rx with join info and returns rx.  On failure,
   returns NULL.  Reasons for failure include shmlog is a NULL pointer,
   misaligned, or does obviously not point to a quic_log_abi object. */

fd_quic_log_rx_t *
fd_quic_log_rx_join( fd_quic_log_rx_t * rx,
                     void *             shmlog );

/* fd_quic_log_rx_leave leaves a local consumer-side join to a quic_log. */

void *
fd_quic_log_rx_leave( fd_quic_log_rx_t * log );

/* fd_quic_log_rx_data_const returns a pointer to the data record.  log
   is a local join to a quic_log object.  The chunk value is taken from
   a frag_meta received via the mcache of this quic_log object/ */

FD_FN_CONST static inline void const *
fd_quic_log_rx_data_const( fd_quic_log_rx_t const * rx,
                           ulong                    chunk ) {
  return fd_chunk_to_laddr_const( rx->base, chunk );
}

/* fd_quic_log_rx_is_safe returns 0 if a log message read is guaranteed
   to be out of bounds.  Otherwise returns 1 (does not imply that the
   read is guaranteed to be within bounds, though). */

FD_FN_PURE static inline int
fd_quic_log_rx_is_safe( fd_quic_log_rx_t const * rx,
                        ulong                    chunk,
                        ulong                    sz ) {
  ulong msg_lo  = (ulong)fd_chunk_to_laddr_const( rx->base, chunk );
  ulong msg_hi  = msg_lo + sz;
  ulong msg_min = rx->data_lo_laddr;
  ulong msg_max = rx->data_hi_laddr;
  return msg_lo>=msg_min && msg_hi<=msg_max && msg_lo<=msg_hi;
}

/* fd_quic_log_sig_event extracts the event ID from the 'sig' field of
   a frag_meta record.  (bits 0..16) */

static inline uint
fd_quic_log_sig_event( ulong sig ) {
  return (uint)( sig & USHORT_MAX );
}

/* FIXME high-level API for reads */

/* fd_quic_log_rx_tail reads the last record relative to seq[0].
   This function is only useful when producer and consumer run on the
   same thread. */

static inline fd_frag_meta_t const *
fd_quic_log_rx_tail( fd_quic_log_rx_t const * rx,
                     ulong                    idx ) {
  ulong seq = fd_mcache_seq_query( rx->mcache_seq ) - 1UL - idx;
  return rx->mcache + fd_mcache_line_idx( seq, rx->depth );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_log_user_h */
