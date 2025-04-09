#ifndef HEADER_fd_src_waltz_h2_fd_h2_rbuf_h
#define HEADER_fd_src_waltz_h2_fd_h2_rbuf_h

/* fd_h2_rbuf.h provides a byte oriented unaligend ring buffer. */

#include "fd_h2_base.h"
#include "../../util/log/fd_log.h"

struct fd_h2_rbuf {
  uchar * buf0;    /* points to first byte of buffer */
  uchar * buf1;    /* points one past last byte of buffer */
  uchar * lo;      /* in [buf0,buf1) */
  uchar * hi;      /* in [buf0,buf1) */
  ulong   lo_off;
  ulong   hi_off;
  ulong   bufsz;
};

FD_PROTOTYPES_BEGIN

/* fd_h2_rbuf_init initializes an h2_rbuf backed by the given buffer.
   On return, h2_rbuf has a read-write interested in buf.  bufsz has no
   alignment requirements. */

static inline fd_h2_rbuf_t *
fd_h2_rbuf_init( fd_h2_rbuf_t * rbuf,
                 void *         buf,
                 ulong          bufsz ) {
  *rbuf = (fd_h2_rbuf_t) {
    .buf0  = (uchar *)buf,
    .buf1  = (uchar *)buf+bufsz,
    .lo    = (uchar *)buf,
    .hi    = (uchar *)buf,
    .bufsz = bufsz
  };
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
  return (ulong)fd_long_max( 0L, rbuf->buf1 - rbuf->buf0 - used );
}

/* fd_h2_rbuf_push appends a series of newly received bytes into rbuf.
   Returns chunk_sz.

   WARNING: The caller must not pass a chunk_sz larger than
   fd_h2_rbuf_free_sz bytes. */

static inline void
fd_h2_rbuf_push( fd_h2_rbuf_t * rbuf,
                 void const *   chunk,
                 ulong          chunk_sz ) {
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  rbuf->hi_off += chunk_sz;

  if( FD_UNLIKELY( hi+chunk_sz > rbuf->buf1 ) ) {
    /* Split copy */
    if( FD_UNLIKELY( lo>hi ) ) {
      FD_LOG_CRIT(( "rbuf overflow: buf_sz=%lu lo=%ld hi=%ld chunk_sz=%lu",
                    rbuf->bufsz, rbuf->lo-buf0, rbuf->hi-buf0, chunk_sz ));
    }
    ulong part1 = (ulong)( buf1-hi        );
    ulong part2 = (ulong)( chunk_sz-part1 );
    fd_memcpy( hi,                    chunk,         part1 );
    fd_memcpy( buf0, (void *)( (ulong)chunk+part1 ), part2 );
    rbuf->hi = buf0+part2;
    return;
  }

  /* One-shot copy */
  uchar * new_hi = hi+chunk_sz;
  if( new_hi==buf1 ) new_hi = buf0;
  fd_memcpy( hi, chunk, chunk_sz );
  rbuf->hi = new_hi;
  return;
}

/* fd_h2_rbuf_peek_used returns a pointer to the first contiguous
   fragment of unconsumed data.  *sz is set to the number of contiguous
   bytes starting at rbuf->lo.  *split_sz is set to the number of bytes
   that are unconsumed, but in a separate fragment.  The caller may
   mangle bytes in [retval,retval+sz) if it consumes these bytes
   immediately afterwards. */

static inline uchar *
fd_h2_rbuf_peek_used( fd_h2_rbuf_t * rbuf,
                      ulong *        sz,
                      ulong *        split_sz ) {
  ulong used_sz = fd_h2_rbuf_used_sz( rbuf );
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  uchar * end  = lo+used_sz;
  /* FIXME make this branchless */
  if( end<=buf1 ) {
    *sz       = (ulong)( hi - lo );
    *split_sz = 0UL;
  } else {
    *sz       = (ulong)( buf1 - lo   );
    *split_sz = (ulong)( hi   - buf0 );
  }
  return lo;
}

/* fd_h2_rbuf_peek_free is like fd_h2_rbuf_peek_used, but refers to the
   free region. */

static inline uchar *
fd_h2_rbuf_peek_free( fd_h2_rbuf_t * rbuf,
                      ulong *        sz,
                      ulong *        split_sz ) {
  ulong free_sz = fd_h2_rbuf_free_sz( rbuf );
  uchar * buf0 = rbuf->buf0;
  uchar * buf1 = rbuf->buf1;
  uchar * lo   = rbuf->lo;
  uchar * hi   = rbuf->hi;
  uchar * end  = hi+free_sz;
  /* FIXME make this branchless */
  if( end<=buf1 ) {
    *sz       = (ulong)( buf1 - hi );
    *split_sz = 0UL;
  } else {
    *sz       = (ulong)( buf1 - hi );
    *split_sz = (ulong)( buf0 - lo );
  }
  return hi;
}

/* fd_h2_rbuf_skip frees n bytes from rbuf.  Freeing more bytes than
   returned by fd_h2_rbuf_used_sz corrupts the buffer state. */

static inline void
fd_h2_rbuf_skip( fd_h2_rbuf_t * rbuf,
                 ulong          n ) {
  uchar * lo    = rbuf->lo;
  ulong   bufsz = rbuf->bufsz;
  uchar * buf1  = rbuf->buf1;
  rbuf->lo_off += n;
  lo += n;
  if( FD_UNLIKELY( lo>=buf1 ) ) {
    lo -= bufsz;
  }
  rbuf->lo = lo;
}

/* fd_h2_rbuf_alloc marks the next n free bytes as used. */

static inline void
fd_h2_rbuf_alloc( fd_h2_rbuf_t * rbuf,
                   ulong          n ) {
  uchar * hi    = rbuf->hi;
  ulong   bufsz = rbuf->bufsz;
  uchar * buf1  = rbuf->buf1;
  rbuf->hi_off += n;
  hi += n;
  if( FD_UNLIKELY( hi>=buf1 ) ) {
    hi -= bufsz;
  }
  rbuf->hi = hi;
}

/* fd_h2_rbuf_pop consumes n bytes from rbuf.  n is the number of bytes
   to consume.  n is assumed to be <= fd_h2_rbuf_used(rbuf).  scratch
   points to scratch memory with space for n bytes.

   If the bytes are available contiguously in rbuf, returns a pointer to
   them.  Otherwise, the bytes are copied into scratch.  The returned
   pointer is valid until the next mutating rbuf operation. */

static inline uchar *
fd_h2_rbuf_pop( fd_h2_rbuf_t * rbuf,
                uchar *        scratch,
                ulong          n ) {
  uchar * lo    = rbuf->lo;
  uchar * buf0  = rbuf->buf0;
  uchar * buf1  = rbuf->buf1;
  ulong   bufsz = rbuf->bufsz;
  uchar * ret   = lo;
  rbuf->lo_off += n;
  uchar * end = lo+n;
  if( FD_UNLIKELY( (lo+n)>=buf1 ) ) {
    end -= bufsz;
  }
  if( FD_UNLIKELY( (lo+n)>buf1 ) ) {
    ulong part0 = (ulong)( buf1-lo );
    ulong part1 = n-part0;
    fd_memcpy( scratch,       lo,   part0 );
    fd_memcpy( scratch+part0, buf0, part1 );
    ret = scratch;
  }
  rbuf->lo = end;
  return ret;
}

static inline void
fd_h2_rbuf_pop_copy( fd_h2_rbuf_t * rbuf,
                     void *         out,
                     ulong          n ) {
  uchar * lo    = rbuf->lo;
  uchar * buf0  = rbuf->buf0;
  uchar * buf1  = rbuf->buf1;
  ulong   bufsz = rbuf->bufsz;
  rbuf->lo_off += n;
  uchar * end = lo+n;
  if( FD_UNLIKELY( (lo+n)>=buf1 ) ) {
    end -= bufsz;
  }
  if( FD_UNLIKELY( (lo+n)>buf1 ) ) {
    ulong part0 = (ulong)( buf1-lo );
    ulong part1 = n-part0;
    fd_memcpy(                  out,         lo,   part0 );
    fd_memcpy( (void *)( (ulong)out+part0 ), buf0, part1 );
  } else {
    fd_memcpy( out, lo, n );
  }
  rbuf->lo = end;
}

FD_FN_PURE static inline int
fd_h2_rbuf_is_empty( fd_h2_rbuf_t const * rbuf ) {
  return rbuf->lo_off==rbuf->hi_off;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_rbuf_h */
