#ifndef HEADER_fd_src_waltz_quic_log_fd_quic_log_tx_h
#define HEADER_fd_src_waltz_quic_log_fd_quic_log_tx_h

/* fd_quic_log_tx.h provides internal APIs for high performance
   logging of events.  Programs that wish to read logs should use
   fd_quic_log_user.h instead.

   These are designed to handle millions of events per second in a
   production environment without significantly impacting application
   performance.  That said, the below inlines still contribute to code
   bloat so they should be used sparingly in the hot path.

   Currently uses an unstable custom binary log format, could be made
   compatible with qlog in the future.

   ### Architecture

   fd_quic_log is split into an internal API (initialization, producing
   logs) and a public API (reading logs).  This allows for changes to
   log producers without having to recompile consumers.

   Public APIs (fd_quic_log_user.h):
   - quic_log_abi: Stable ABI for a quic_log shared memory object
   - quic_log_rx: Log consumer join to a quic_log (via quic_log_abi)

   Internal APIs (fd_quic_log_tx.h which is this file):
   - quic_log_buf: SPMC queue for log messages (implements quic_log_abi)
   - quic_log_tx: Log producer join to a quic_log_buf */

#include "fd_quic_log_user.h"
#include "../../../tango/mcache/fd_mcache.h"
#include "../../../tango/dcache/fd_dcache.h"

/* FD_QUIC_LOG_MTU is the max message size of a quic_log_buf.
   This parameter can be modified without changes to quic_log_abi. */

#define FD_QUIC_LOG_MTU FD_CHUNK_SZ

/* A quic_log_buf object is an SPMC queue for log messages suitable for
   use over shared memory.  fd_quic_log_buf_t is the header of a
   quic_log_buf object.

   A quic_log_buf is joined by at most one producer (via quic_log_tx) and
   an arbitrary number of consumers (via quic_log_rx).  A producer and
   the consumers do not need to be in the same address space.  Consumers
   do not need to write to quic_log_buf memory. */

struct __attribute__((aligned(64))) fd_quic_log_buf {
  /* Public ABI for consumers */
  fd_quic_log_abi_t abi;

  /* Private params follow ... */
  ulong magic;
  uint  dcache_off;
  uint  chunk0;
  uint  wmark;
};

typedef struct fd_quic_log_buf fd_quic_log_buf_t;

/* FD_QUIC_LOG_BUF_MAGIC is used to signal the layout of shared memory
   region of a quic_log_buf. */

#define FD_QUIC_LOG_BUF_MAGIC (0x11df9ddf66ea2912)

/* FD_QUIC_LOG_BUF_{ALIGN,FOOTPRINT} specify parameters for the memory
   region backing a quic_log_buf.  U.B. if depth is invalid. */

#define FD_QUIC_LOG_BUF_ALIGN FD_QUIC_LOG_ALIGN
#define FD_QUIC_LOG_BUF_FOOTPRINT(depth)                                                                      \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,                       \
    FD_QUIC_LOG_BUF_ALIGN, sizeof(fd_quic_log_buf_t) ),                                                       \
    FD_MCACHE_ALIGN,       FD_MCACHE_FOOTPRINT( depth, 0 ) ),                                                 \
    FD_DCACHE_ALIGN,       FD_DCACHE_FOOTPRINT( FD_DCACHE_REQ_DATA_SZ( FD_QUIC_LOG_MTU, depth, 1, 1 ), 0 ) ), \
    FD_QUIC_LOG_BUF_ALIGN )

FD_PROTOTYPES_BEGIN

/* fd_quic_log_buf_align returns FD_QUIC_LOG_BUF_ALIGN. */

FD_FN_CONST ulong
fd_quic_log_buf_align( void );

/* fd_quic_log_buf_footprint returns the required size of a memory region
   backing a quic_log_buf.  Silently returns 0 if depth is invalid (thus
   can be used as a quick way to check if depth is valid). */

FD_FN_CONST ulong
fd_quic_log_buf_footprint( ulong depth );

/* fd_quic_log_buf_new formats a memory region as a quic_log_buf.  Returns
   NULL and logs warning on failure (e.g. invalid depth).  On success,
   returns shmlog which now ready for producer joins
   (fd_quic_log_buf_join) and consumer joins (fd_quic_log_rx_join). */

void *
fd_quic_log_buf_new( void * shmlog,
                     ulong  depth );

/* fd_quic_log_buf_delete releases the memory region backing a
   quic_log_buf back to the caller.  Assumes that there are no active
   joins to quic_log_buf. */

void *
fd_quic_log_buf_delete( void * shmlog );

FD_PROTOTYPES_END

/* fd_quic_log_tx describes a producer-side join to a fd_quic_log_buf. */

struct fd_quic_log_tx {
  fd_frag_meta_t * mcache;
  ulong *          mcache_seq;
  void *           base;
  ulong            depth;
  ulong            seq;
  uint             chunk;
  uint             chunk0;
  uint             wmark;
};

typedef struct fd_quic_log_tx fd_quic_log_tx_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_log_tx_join joins the caller thread to a quic_log_buf as a
   producer.  shmlog points to a quic_log_buf object in the local
   address space.  On success, fills tx with join info and returns tx.
   On failure, returns NULL.  Reasons for failure include shmlog is a
   NULL pointer or does obviously not point to a quic_log_buf object.
   It is U.B. to join multiple producers to the same shmlog. */

fd_quic_log_tx_t *
fd_quic_log_tx_join( fd_quic_log_tx_t * tx,
                     void *             shmlog );

/* fd_quic_log_tx_leave releases the caller thread from the
   quic_log_buf.  It is safe to call this function when consumers are
   still attached. */

void *
fd_quic_log_tx_leave( fd_quic_log_tx_t * logger );

/* fd_quic_log_seq_update updates the seq[0] parameter.
   (See fd_mcache.h) */

static inline void
fd_quic_log_tx_seq_update( fd_quic_log_tx_t * log ) {
  fd_mcache_seq_update( log->mcache_seq, log->seq );
}

/* fd_quic_log_tx_prepare starts a new log message write.  Any other
   in-flight write by this producer is dropped.  Returns a pointer to
   the log message buffer (in memory owned by quic_log_buf).  Up to
   FD_QUIC_LOG_BUF_MTU bytes may be written to this pointer. */

static inline void *
fd_quic_log_tx_prepare( fd_quic_log_tx_t * log ) {
  return fd_chunk_to_laddr( log->base, log->chunk );
}

/* fd_quic_log_tx_submit submits an in-flight log message write. */

static inline void
fd_quic_log_tx_submit( fd_quic_log_tx_t * tx,
                       ulong              sz,     /* in [0,FD_QUIC_LOG_BUF_MTU) */
                       ulong              sig,    /* see fd_quic_log_sig() */
                       long               ts ) {
  fd_frag_meta_t * mcache  = tx->mcache;
  ulong            chunk   = tx->chunk;
  ulong            depth   = tx->depth;
  ulong            seq     = tx->seq;
  ulong            ctl     = fd_frag_meta_ctl( 0, 1, 1, 0 );
  uint             ts_comp = (uint)fd_frag_meta_ts_comp( ts );
  ulong            chunk0  = tx->chunk0;
  uint             wmark   = tx->wmark;

#if FD_HAS_SSE
#define fd_quic_log_publish fd_mcache_publish_sse
#else
#define fd_quic_log_publish fd_mcache_publish
#endif
  fd_quic_log_publish( mcache, depth, seq, sig, chunk, sz, ctl, 0, ts_comp );
#undef fd_quic_log_publish

  tx->seq   = fd_seq_inc( seq, 1UL );
  tx->chunk = (uint)fd_dcache_compact_next( chunk, sz, chunk0, wmark );
}

static inline ulong
fd_quic_log_sig( uint event ) {
  return (ulong)event;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_log_fd_quic_log_tx_h */
