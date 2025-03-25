#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_h

/* fd_h2_rbuf.h provides an API for recovering contiguous HTTP/2 frames
   from a fragmented ordered stream of chunks. */

#include "fd_h2_base.h"
#include "../../util/log/fd_log.h"

#if FD_HAS_HOSTED
#include <sys/uio.h>
#endif

/* fd_h2_rbuf is a circular buffer.  It is intended for use as a
   connection-level HTTP/2 receive buffer.  Users can blindly push
   ordered TCP stream data (e.g. as received from a socket) into an
   h2_rbuf, and pop contiguous HTTP/2 frames for processing.

   The main task of h2_rbuf is to expose frames via a single, contiguous
   span of memory.  This avoids pushing complex defrag logic in HTTP/2
   frame handlers.  Defragging is done lazily (a message can start at
   the end of the buffer and wrap around to the beginning).

   This buffer is not designed for high-performance.  It is technically
   possible to eliminate this buffer entirely using a custom TCP and TLS
   record layer implementation, but this is out of scope for now.

   h2_buf maintains the invariant that the buffer can only be half full. */

struct fd_h2_rbuf {
  uchar * buf0;
  uchar * buf1;
  uchar * lo;
  uchar * hi;
  ulong   lo_off;
  ulong   hi_off;
  ulong   frame_max;
};

typedef struct fd_h2_rbuf fd_h2_rbuf_t;

FD_PROTOTYPES_BEGIN

/* fd_h2_rbuf_init initializes an h2_rbuf backed by the given buffer.
   On return, h2_rbuf has a read-write interested in buf.  bufsz has no
   alignment requirements. */

static inline fd_h2_rbuf_t *
fd_h2_rbuf_init( fd_h2_rbuf_t * rbuf,
                 void *         buf,
                 ulong          bufsz ) {
  if( FD_UNLIKELY( bufsz<64 ) ) {
    FD_LOG_WARNING(( "h2_rbuf init failed: bufsz too small" ));
    return NULL;
  }
  *rbuf = (fd_h2_rbuf_t) {
    .buf0      = (uchar *)buf,
    .buf1      = (uchar *)buf+bufsz,
    .lo        = (uchar *)buf,
    .hi        = (uchar *)buf,
    .frame_max = bufsz/2
  };
  return rbuf;
}

/* fd_h2_rbuf_fini destroys an h2_rbuf and releases the read-write
   interest in buf.  Returns rbuf. */

static inline void *
fd_h2_rbuf_fini( fd_h2_rbuf_t * rbuf ) {
  return rbuf;
}

/* fd_h2_rbuf_used_sz returns the number of unconsumed bytes in rbuf. */

FD_FN_PURE static inline ulong
fd_h2_rbuf_used_sz( fd_h2_rbuf_t const * rbuf ) {
  return rbuf->hi_off - rbuf->lo_off;
}

/* fd_h2_rbuf_free_sz returns the number of bytes that can be appended
   using fd_h2_rbuf_push. */

FD_FN_PURE static inline ulong
fd_h2_rbuf_free_sz( fd_h2_rbuf_t const * rbuf ) {
  long used = (long)fd_h2_rbuf_used_sz( rbuf );
  return (ulong)fd_long_max( 0L, (long)rbuf->frame_max - used );
}

/* fd_h2_rbuf_push appends a series of newly received bytes into rbuf.
   Returns chunk_sz.

   WARNING: The caller must not pass a chunk_sz larger than
   fd_h2_rbuf_free_sz bytes. */

static inline void
fd_h2_rbuf_push( fd_h2_rbuf_t * rbuf,
                 uchar const *  chunk,
                 ulong          chunk_sz ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  rbuf->hi_off += chunk_sz;

  if( FD_UNLIKELY( hi+chunk_sz > rbuf->buf1 ) ) {
    /* Split copy */
    if( FD_UNLIKELY( lo>hi ) ) {
      FD_LOG_CRIT(( "rbuf overflow: buf_sz=%ld lo=%ld hi=%ld chunk_sz=%lu",
                    rbuf->buf1-buf0, rbuf->lo-buf0, rbuf->hi-buf0, chunk_sz ));
    }
    ulong part1 = (ulong)( buf1-hi        );
    ulong part2 = (ulong)( chunk_sz-part1 );
    fd_memcpy( hi,   chunk,       part1 );
    fd_memcpy( buf0, chunk+part1, part2 );
    rbuf->hi = buf0+part2;
    return;
  }

  /* One-shot copy */
  uchar * new_hi = hi+chunk_sz;
  if( FD_UNLIKELY( (lo>hi) != (lo>new_hi) ) ) {
    FD_LOG_CRIT(( "rbuf overflow: buf_sz=%ld lo=%ld hi=%ld chunk_sz=%lu",
                  rbuf->buf1-buf0, rbuf->lo-buf0, rbuf->hi-buf0, chunk_sz ));
  }
  if( new_hi==buf1 ) new_hi = buf0;
  fd_memcpy( hi, chunk, chunk_sz );
  rbuf->hi = new_hi;
  return;
}

/* fd_h2_rbuf_peek_head returns a pointer to the first contiguous
   fragment of unconsumed data.  *sz is set to the number of contiguous
   bytes starting at rbuf->lo.  *split_sz is set to the number of bytes
   that are unconsumed, but in a separate fragment.  The caller may
   mangle bytes in [retval,retval+sz) if it consumes these bytes
   immediately afterwards. */

static inline uchar *
fd_h2_rbuf_peek_head( fd_h2_rbuf_t * rbuf,
                      ulong *        sz,
                      ulong *        split_sz ) {
  /* FIXME make this branchless */
  if( rbuf->lo <= rbuf->hi ) {
    *sz       = (ulong)( rbuf->hi - rbuf->lo );
    *split_sz = 0UL;
  } else {
    *sz       = (ulong)( rbuf->buf1 - rbuf->lo   );
    *split_sz = (ulong)( rbuf->hi   - rbuf->buf0 );
  }
  return rbuf->lo;
}

/* fd_h2_rbuf_skip frees n bytes from rbuf.  Freeing more bytes than
   returned by fd_h2_rbuf_used_sz corrupts the buffer state. */

static inline void
fd_h2_rbuf_skip( fd_h2_rbuf_t * rbuf,
                 ulong          n ) {
  uchar * lo   = rbuf->lo;
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  rbuf->lo_off += n;
  lo += n;
  if( FD_UNLIKELY( lo>=buf1 ) ) {
    lo += buf0-buf1;
  }
  rbuf->lo = lo;
}

/* fd_h2_rbuf_pop frees n bytes from rbuf, and returns a pointer to the
   bytes (guaranteed contiguous).  n<=frame_max.  If necessary, the
   bytes are moved within buffer.  The returned pointer is valid until
   the next mutating rbuf operation. */

static inline uchar *
fd_h2_rbuf_pop( fd_h2_rbuf_t * rbuf,
                ulong          n ) {
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * ret  = lo;
  rbuf->lo_off += n;
  lo += n;
  if( FD_UNLIKELY( lo>=buf1 ) ) {
    lo += buf0-buf1;
    ulong part0 = (ulong)( buf1-ret );
    ulong part1 = n-part0;
    fd_memcpy( hi,       ret,  part0 );
    fd_memcpy( hi+part0, buf0, part1 );
    ret = hi;
  }
  rbuf->lo = lo;
  return ret;
}

/* fd_h2_rbuf_compact pulls all bytes in the buffer into a single
   contiguous chunk. */

static inline int
fd_h2_rbuf_compact( fd_h2_rbuf_t * rbuf ) {
  if( FD_UNLIKELY( rbuf->lo <= rbuf->hi ) ) return FD_H2_SUCCESS;

  ulong   part1  = (ulong)( rbuf->buf1 - rbuf->lo   );
  ulong   part2  = (ulong)( rbuf->hi   - rbuf->buf0 );
  uchar * new_lo = rbuf->hi;
  uchar * new_hi = new_lo + part1 + part2;
  if( FD_UNLIKELY( ( new_hi > rbuf->buf1 ) |
                   ( new_hi > rbuf->lo   ) ) ) {
    /* Unreachable if h2_rbuf APIs used correctly */
    FD_LOG_WARNING(( "Cannot compact h2_rbuf: buffer full" ));
    return FD_H2_ERR_INTERNAL;
  }

  memmove( new_lo,       rbuf->lo,   part1 );
  memmove( new_lo+part1, rbuf->buf0, part2 );
  rbuf->lo = new_lo;
  rbuf->hi = new_hi;

  return FD_H2_SUCCESS;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_h */
