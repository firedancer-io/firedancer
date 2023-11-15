#ifndef HEADER_fd_src_util_io_fd_io_h
#define HEADER_fd_src_util_io_fd_io_h

/* API for platform agnostic high performance stream I/O.  Summary:

   Read at least min bytes directly from stream fd into size max buffer
   buf (1<=min<=max):

     ulong rsz; int err = fd_io_read( fd, buf, min, max, &rsz );
     if     ( FD_LIKELY( err==0 ) ) ... success, rsz in [min,max], buf updated
     else if( FD_LIKELY( err< 0 ) ) ... EOF encountered, rsz is [0,min), buf updated
     else                           ... I/O error, rsz is zero, buf clobbered
                                    ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                    ... fd should be considered failed

   This usage will block (even if the stream is non-blocking) until min
   bytes are read, EOF is encountered or there is an I/O error.  As
   such, the min==1 case behaves like a POSIX read on a blocking stream.
   The min==max case will read an exact number of bytes from the stream
   and return an error if this is not possible.  The 1<min<max case is
   useful for implementing buffered I/O.

   A non-blocking read on a non-blocking stream is possible by setting
   min==0:

     ulong rsz; int err = fd_io_read( fd, buf, 0UL, max, &rsz );
     if     ( FD_LIKELY( err==0      ) ) ... success, rsz in [1,max], buf updated
     else if( FD_LIKELY( err==EAGAIN ) ) ... try again later, rsz is zero, buf unchanged
     else if( FD_LIKELY( err< 0      ) ) ... EOF encountered, rsz is zero, buf unchanged
     else                                ... I/O error, rsz is zero, buf clobbered
                                         ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                         ... fd should be considered failed

   (If min==0 and stream fd is blocking, the EAGAIN case will never
   occur.)

   Write is nearly symmetrical to read.

   Write at least min byte and at most max bytes from buf into stream fd
   (1<=min<=max):

     ulong wsz; int err = fd_io_write( fd, buf, min, max, &wsz );
     if( FD_LIKELY( err==0 ) ) ... success, wsz in [min,max]
     else                      ... I/O error, wsz is zero, how much of buf was streamed before the error is unknown
                               ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                               ... fd should be considered failed

   This usage will block (even if the stream is non-blocking) until min
   bytes are written or there is an I/O error.  As such, the min==1 case
   behaves like a POSIX write on a stream.  The min==max case will write
   an exact number of bytes to fd and give an error if this is not
   possible.  The 1<min<max case is useful for implementing buffered
   I/O.

   A non-blocking write on a non-blocking stream is possible by setting
   min==0:

     ulong wsz; int err = fd_io_write( fd, buf, 0UL, max, &wsz );
     if     ( FD_LIKELY( err==0      ) ) ... success, wsz in [1,max]
     else if( FD_LIKELY( err==EAGAIN ) ) ... try again later, wsz is zero
     else                                ... I/O error, wsz is zero, how much of buf was streamed before the error is unknown
                                         ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                         ... fd should be considered failed

   (If min==0 and stream fd is blocking, the EAGAIN case will never
   occur.)

   Each call above typically requires at least one system call.  This
   can be inefficient if doing lots of tiny reads and writes.  For
   higher performance usage in cases like this, buffered I/O APIs are
   also provided.

   Buffered reads:

     ... setup buffered reads from stream fd using the rbuf_sz size
     ... buffer rbuf (rbuf_sz>0) as the read buffer

     fd_io_buffered_istream_t in[1];
     fd_io_buffered_istream_init( in, fd, rbuf, rbuf_sz );
     ... in is initialized and has ownership of fd and rbuf

     ... accessors (these return the values used to init in)

     int    fd      = fd_io_buffered_istream_fd     ( in );
     void * rbuf    = fd_io_buffered_istream_rbuf   ( in );
     ulong  rbuf_sz = fd_io_buffered_istream_rbuf_sz( in );

     ... read sz bytes from a buffered stream

     int err = fd_io_buffered_istream_read( in, buf, sz );
     if     ( FD_LIKELY( err==0 ) ) ... success, buf holds the next sz bytes of stream
     else if( FD_LIKELY( err< 0 ) ) ... EOF before sz bytes could be read, buf clobbered
     else                           ... I/O error, buf clobbered
                                    ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                    ... in and fd should be considered failed

     ... skip sz bytes in a buffered stream

     int err = fd_io_buffered_istream_skip( in, sz );
     if     ( FD_LIKELY( err==0 ) ) ... success, sz bytes skipped
     else if( FD_LIKELY( err< 0 ) ) ... EOF before sz bytes could be skipped
     else                           ... I/O error
                                    ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                    ... in and fd should be considered failed

     ... zero-copy read bytes from a buffered stream

     ulong        peek_sz = fd_io_buffered_istream_peek_sz( in ); ... returns number of bytes currently buffered
     void const * peek    = fd_io_buffered_istream_peek   ( in ); ... returns location of current buffered bytes

     fd_io_buffered_istream_seek( in, sz ); ... consume sz currently buffered bytes, sz in [0,peek_sz]

     ... read buffering control

     int err = fd_io_buffered_istream_fetch( in );
     if     ( FD_LIKELY( err==0      ) ) ... success,         peek_sz updated to at most rbuf_sz
     else if( FD_LIKELY( err< 0      ) ) ... end-of-file,     peek_sz updated to unconsumed bytes remaining (at most rbuf_sz)
     else if( FD_LIKELY( err==EAGAIN ) ) ... try again later, peek_sz unchanged
     else                                ... I/O error,       peek_sz unchanged
                                         ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                         ... in and fd should be considered failed

     (The EAGAIN case only applies for a non-blocking stream.)

     TODO: consider option to do block until a min level?

     ... finish using buffered stream

     fd_io_buffered_istream_fini( in );
     ... in is not in use and no longer has ownership of fd and rbuf.
     ... IMPORTANT! buffering might have pushed fd's file offset beyond
     ... the bytes the user has actually consumed.  It is the user's
     ... responsibility for handling this.  (Usually nothing needs to be
     ... or can be done as either the next operation is to close fd or
     ... the fd does not support seeking.)

   There are nearly symmetric APIs for buffered writes.

     ... start buffered writing to stream fd using the wbuf_sz size
     ... buffer wbuf (wbuf_sz>0) as the write buffer

     fd_io_buffered_ostream_t out[1];
     fd_io_buffered_ostream_init( out, fd, wbuf, wbuf_sz );
     ... out is initialized and has ownership of fd and wbuf

     ... accessors (these return the values used to init in)

     int    fd      = fd_io_buffered_ostream_fd     ( out );
     void * wbuf    = fd_io_buffered_ostream_wbuf   ( out );
     ulong  wbuf_sz = fd_io_buffered_ostream_wbuf_sz( out );

     ... write sz bytes to a buffered stream

     int err = fd_io_buffered_ostream_write( out, buf, sz );
     if( FD_LIKELY( err==0 ) ) ... success, sz bytes from have been written from the caller's POV
     else                      ... I/O error, err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                               ... out and fd should be considered failed

     ... zero-copy write bytes to a buffered stream

     ulong  peek_sz = fd_io_buffered_ostream_peek_sz( out ); ... returns amount of unused write buffer space, in [0,wbuf_sz]
     void * peek    = fd_io_buffered_ostream_peek   ( out ); ... returns location of unused write buffer space

     fd_io_buffered_ostream_seek( in, sz ); ... commit sz unused bytes of write buffer, sz in [0,peek_sz]

     ... write buffer control

     int err = fd_io_buffered_ostream_flush( out );
     if( FD_LIKELY( err==0 ) ) ... success, all buffered bytes have been drained to fd
     else                      ... I/O error, err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                               ... out and fd should be considered failed

     (This will block even for a non-blocking stream.)

     ... finish using buffered stream

     fd_io_buffered_ostream_fini( out );
     ... out is not in use and no longer has ownership of fd and wbuf.
     ... IMPORTANT! fini does not do any flushing of buffered writes (as
     ... such fini is guaranteed to always succeed, can be applied to
     ... out's that have failed, etc).  It is the users responsibility
     ... to do any final flush before calling fini.

   More details below. */

#include "../bits/fd_bits.h"

/* fd_io_buffered_{istream,ostream}_t is an opaque handle of an
   {input,output} stream with buffered {reads,writes}.  The internals
   are visible here to facilitate inlining various operations.  This is
   declaration friendly (e.g. usually should just do
   "fd_io_buffered_istream_t in[1];" on the stack to get a suitable
   memory region for the stream state).  These are not meant to be
   persistent or shared IPC. */

struct fd_io_buffered_istream_private {
  int     fd;         /* Open normal-ish file descriptor of stream */
  uchar * rbuf;       /* Read buffer, non-NULL, indexed [0,rbuf_sz), arb alignment */
  ulong   rbuf_sz;    /* Read buffer size, positive */
  ulong   rbuf_lo;    /* Buf bytes [0,rbuf_lo) have already been consumed */
  ulong   rbuf_ready; /* Number of buffered byte that haven't been consumed, 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz */
};

typedef struct fd_io_buffered_istream_private fd_io_buffered_istream_t;

struct fd_io_buffered_ostream_private {
  int     fd;        /* Open normal-ish file descriptor of stream */
  uchar * wbuf;      /* Write buffer, non-NULL, indexed [0,wbuf_sz), arb alignment */
  ulong   wbuf_sz;   /* Write buffer size, positive */
  ulong   wbuf_used; /* Number buffered bytes that haven't been written to fd, in [0,wbuf_sz] */
};

typedef struct fd_io_buffered_ostream_private fd_io_buffered_ostream_t;

FD_PROTOTYPES_BEGIN

/* fd_io_read streams at least dst_min bytes from the given file
   descriptor into the given memory region.  fd should be an open
   normal-ish file descriptor (it is okay for fd to be non-blocking).
   dst points in the caller's address space with arbitrary alignment to
   the first byte of the dst_max byte memory region to use (assumes dst
   non-NULL, and dst_min is at most dst_max).  The caller should not
   read or write this region during the call and no interest in dst is
   retained on return.  If dst_min is 0, this will try to read dst_max
   from the stream exactly once.  If dst_max is 0, is a no-op.

   Returns 0 on success.  On success, *_dst_sz will be the number of
   bytes read into dst.  Will be in [dst_min,dst_max].

   Returns a negative number if end-of-file was encountered before
   reading dst_min bytes.  *_dst_sz will be the number bytes read into
   dst when the end-of-file was encountered.  Will be in [0,dst_min).

   Returns an errno compatible error code on failure (note that all
   errnos are positive).  If errno is anything other than EAGAIN, the
   underlying fd should be considered to be in a failed state such that
   the only valid operation on fd is to close it.  *_dst_sz will be zero
   and the contents of dst will be undefined.  This API fixes up the
   POSIX glitches around EWOULDBLOCK / EAGAIN: if the underlying target
   has EWOULDBLOCK different from EAGAIN and read uses EWOULDBLOCK
   instead of EAGAIN, this will still just return EAGAIN.  EAGAIN will
   only be returned if the underlying fd is non-blocking and dst_min is
   zero.

   TL;DR

   - dst_min is positive:

       ulong dst_sz; int err = fd_io_read( fd, dst, dst_min, dst_max, &dst_sz );
       if     ( FD_LIKELY( err==0 ) ) ... success, dst_sz in [dst_min,dst_max], dst updated
       else if( FD_LIKELY( err< 0 ) ) ... EOF, dst_sz in [0,dst_min), dst updated
       else                           ... I/O error, dst_sz is zero, dst clobbered
                                      ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                      ... fd should be considered failed

     This is equivalent to looping over reads of up to dst_max in size
     from fd until at least dst_min bytes are read.  It does not matter
     if fd is blocking or not.

   - dst_min is zero and fd is blocking:

       ulong dst_sz; int err = fd_io_read( fd, dst, dst_min, dst_max, &dst_sz );
       if     ( FD_LIKELY( err==0 ) ) ... success, dst_sz in [1,dst_max], dst updated
       else if( FD_LIKELY( err< 0 ) ) ... EOF, dst_sz is zero, dst unchanged
       else                           ... I/O error, dst_sz is zero, dst clobbered
                                      ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                      ... fd should be considered failed

     This is equivalent to a single read of dst_max size on a blocking
     fd.

   - dst_min is zero and fd is non-blocking:

       ulong dst_sz; int err = fd_io_read( fd, dst, dst_min, dst_max, &dst_sz );
       if     ( FD_LIKELY( err==0      ) ) ... success, dst_sz in [1,dst_max], dst updated
       else if( FD_LIKELY( err==EAGAIN ) ) ... no data available now, try again later, dst_sz is zero, dst unchanged
       else if( FD_LIKELY( err< 0      ) ) ... EOF, dst_sz is zero, dst unchanged
       else                                ... I/O error, dst_sz is zero, dst clobbered
                                           ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                           ... fd should be considered failed

     This is equivalent to a single read of dst_max size on a
     non-blocking fd (with the POSIX glitches around EAGAIN /
     EWOULDBLOCK cleaned up). */

int
fd_io_read( int     fd,
            void *  dst,
            ulong   dst_min,
            ulong   dst_max,
            ulong * _dst_sz );

/* fd_io_write behaves virtually identical to fd_io_read but the
   direction of the transfer is from memory to the stream and there is
   no notion of EOF handling.  Assumes src is non-NULL,
   src_min<=src_max, src_sz is non-NULL and non-overlapping with src.
   If src_max is 0, is a no-op.  Summarizing:

   - src_min is positive:

       ulong src_sz; int err = fd_io_write( fd, src, src_min, src_max, &src_sz );
       if( FD_LIKELY( err==0 ) ) ... success, src_sz in [src_min,src_max]
       else                      ... I/O error, src_sz is zero
                                 ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                 ... fd should be considered failed

     This is equivalent to looping over writes of up to src_max in size
     to fd until at least src_min bytes are written.  It does not matter
     if fd is blocking or not.

   - src_min is zero and fd is blocking:

       ulong src_sz; int err = fd_io_write( fd, src, src_min, src_max, &src_sz );
       if( FD_LIKELY( err==0 ) ) ... success, src_sz in [1,src_max]
       else                      ... I/O error, src_sz is zero
                                 ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                 ... fd should be considered failed

     This is equivalent to a single write of src_max size on a blocking
     fd.

   - src_min is zero and fd is non-blocking:

       ulong src_sz; int err = fd_io_write( fd, src, src_min, src_max, &src_sz );
       if     ( FD_LIKELY( err==0      ) ) ... success, src_sz in [1,src_max]
       else if( FD_LIKELY( err==EAGAIN ) ) ... no bytes written, try again later, src_sz is zero
       else                                ... I/O error, src_sz is zero
                                           ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                           ... fd should be considered failed

     This is equivalent to a single write of src_max size on a
     non-blocking fd (with the POSIX glitches around EAGAIN /
     EWOULDBLOCK fixed up). */

int
fd_io_write( int          fd,
             void const * src,
             ulong        src_min,
             ulong        src_max,
             ulong *      _src_sz );

/* fd_io_buffered_read is like fd_io_read but can consolidate many
   tiny reads into a larger fd_io_read via the given buffer.  Unlike
   fd_io_read, dst NULL is okay if dst_sz is 0 (dst_sz 0 is a no-op that
   immediately returns success).  Will block the caller until the read
   is complete or an end-of-file was encountered.

   rbuf points to the first byte of a rbuf_sz size memory region in the
   caller's address space used for read buffering (assumes rbuf is
   non-NULL with arbitrary alignment and rbuf_sz is positive).  On entry
   *_rbuf_lo is where the first byte of unconsumed buffered reads are
   located and *_rbuf_ready is number of unconsumed buffered bytes.
   Assumes 0<=*_rbuf_lo<=(*_rbuf_lo+*_rbuf_ready)<=rbuf_sz.

   Returns 0 on success.  dst will hold dst_sz bytes from the stream.
   *_rbuf_lo and *_rbuf_ready will be updated and the above invariant on
   *_rbuf_lo and *_rbuf_ready will still hold.

   Returns non-zero on failure.  Failure indicates that dst_sz bytes
   could not be read because of an I/O error (return will be a positive
   errno compatible error code) or an end-of-file was encountered
   (return will be a negative number).  dst should be assumed to have
   been clobbered, *_rbuf_lo and *_rbuf_ready will be zero.  If an I/O
   error, the fd should be considered to be in a failed state such that
   the only valid operation on it is to close it.

   IMPORTANT!  This function will only read from fd in multiples of
   rbuf_sz (except for a potentially last incomplete block before an
   end-of-file).  This can be useful for various ultra high performance
   contexts.

   This API usually should not be used directly.  It is mostly useful
   for implementing higher level APIs like fd_io_buffered_istream below. */

int
fd_io_buffered_read( int     fd,
                     void *  dst,
                     ulong   dst_sz,
                     void *  rbuf,
                     ulong   rbuf_sz,
                     ulong * _rbuf_lo,
                     ulong * _rbuf_ready );

/* fd_io_buffered_skip is like fd_io_buffered_read but will skip over
   skip_sz bytes of the stream without copying them into a user buffer.
   If stream fd is seekable (e.g. a normal file), this should be O(1).
   If not (e.g. fd is pipe / socket / stdin / etc), this will block the
   caller until skip_sz bytes have been skipped or an I/O error occurs.

   IMPORTANT!  If stream fd is seekable, POSIX behaviors allow seeking
   past end-of-file (apparently even if fd is read only).  Whether or
   not this is a good idea is debatable.  The result though is this API
   will usually not return an error if skip_sz moves past the
   end-of-file (however, if skip_sz is so large that it causes the file
   offset to overflow, this will return EOVERFLOW).  In particular, this
   API cannot be used to detect end-of-file.

   IMPORTANT!  This function makes no effort to skip in multiples of
   rbuf_sz.  Such is up to the caller to do if such is desirable.

   This API usually should not be used directly.  It is mostly useful
   for implementing higher level APIs like fd_io_buffered_istream below. */

int
fd_io_buffered_skip( int     fd,
                     ulong   skip_sz,
                     void *  rbuf,
                     ulong   rbuf_sz,
                     ulong * _rbuf_lo,
                     ulong * _rbuf_ready );

/* fd_io_buffered_write is like fd_io_write but can consolidate many
   tiny writes into a larger fd_io_write via the given buffer.  Unlike
   fd_io_write, src NULL is okay if src_sz is 0 (src_sz 0 is a no-op
   that immediately returns success).  Will block the caller until the
   write is complete or an end-of-file was encountered.

   wbuf points to the first byte of a wbuf_sz size memory region in the
   caller's address space (assumes wbuf is non-NULL with arbitrary
   alignment and wbuf_sz is positive).  On entry *_wbuf_used is the
   number of bytes in wbuf from previous buffered writes that have not
   yet been streamed out.  Assumes *_wbuf_used is in [0,wbuf_sz].

   Returns 0 on success.  wbuf will hold *_wbuf_used bytes not yet
   written to fd by write and/or previous buffered writes.  The above
   invariant on *_wbuf_used will still hold.

   Returns non-zero on failure.  Failure indicates that src_sz bytes
   could not be written because of an I/O error (return will be a
   positive errno compatible error code).  fd should be considered to be
   in a failed state such that the only valid operation on it is to
   close it.  *_wbuf_used will be 0 and the contents of wbuf will be
   undefined.  Zero or more bytes of previously buffered writes and/or
   src might have been written before the failure.

   IMPORTANT!  This function will only write to fd in multiples of
   wbuf_sz.  This can be useful for various ultra high performance
   contexts.

   This API usually should not be used directly.  It is mostly useful
   for implementing higher level APIs like fd_io_buffered_ostream below. */

int
fd_io_buffered_write( int          fd,
                      void const * src,
                      ulong        src_sz,
                      void *       wbuf,
                      ulong        wbuf_sz,
                      ulong *      _wbuf_used );

/* fd_io_buffered_istream_init initializes in to do buffered reads from
   the given file descriptor.  in is an unused location that should hold
   the buffering state, fd is an open normal-ish file descriptor, rbuf
   points to the first byte in the caller's address space to an unused
   rbuf_sz size memory region to use for read buffering (assumes rbuf is
   non-NULL with arbitrary alignment and rbuf_sz is positive).  Returns
   in and on return in will be initialized.  in will have ownership of
   fd and rbuf while initialized. */

static inline fd_io_buffered_istream_t *
fd_io_buffered_istream_init( fd_io_buffered_istream_t * in,
                             int                        fd,
                             void *                     rbuf,
                             ulong                      rbuf_sz ) {
  in->fd         = fd;
  in->rbuf       = (uchar *)rbuf;
  in->rbuf_sz    = rbuf_sz;
  in->rbuf_lo    = 0UL;
  in->rbuf_ready = 0UL;
  return in;
}

/* fd_io_buffered_istream_{fd,rbuf,rbuf_sz} return the corresponding
   value used to initialize in.  Assumes in is initialized. */

FD_FN_PURE static inline int    fd_io_buffered_istream_fd     ( fd_io_buffered_istream_t const * in ) { return in->fd;      }
FD_FN_PURE static inline void * fd_io_buffered_istream_rbuf   ( fd_io_buffered_istream_t const * in ) { return in->rbuf;    }
FD_FN_PURE static inline ulong  fd_io_buffered_istream_rbuf_sz( fd_io_buffered_istream_t const * in ) { return in->rbuf_sz; }

/* fd_io_buffered_istream_fini finalizes a buffered input stream.
   Assumes in is initialized.  On return in will no longer be
   initialized and ownership the underlying fd and rbuf will return to
   the caller.

   IMPORTANT!  THIS WILL NOT REPOSITION THE UNDERLYING FD FILE OFFSET
   (SUCH MIGHT NOT EVEN BE POSSIBLE) TO "UNREAD" ANY UNCONSUMED BUFFERED
   DATA. */

static inline void
fd_io_buffered_istream_fini( fd_io_buffered_istream_t * in ) {
  (void)in;
}

/* fd_io_buffered_istream_read reads dst_sz bytes from in to dst,
   reading ahead as convenient.  Assumes in is initialized.  dst /
   dst_sz have the same meaning / restrictions as fd_io_buffered_read.
   Returns 0 on success and non-zero on failure.  Failure interpretation
   is the same as fd_io_buffered_read.  On failure, in and the
   underlying file descriptor should be considered to be in a failed
   state (e.g. the only valid thing to do to in is fini and the only
   valid thing to do to fd is close).

   IMPORTANT!  If fd_io_buffered_istream_{fetch,skip} below are never
   used (or only used to skip in multiplies of rbuf_sz), all the reads
   from the underlying stream will always be at multiples of rbuf_sz
   from the file offset when the in was initialized and a multiple of
   rbuf_sz in size (except possibly a final read to the end-of-file).
   This can be beneficial in various high performance I/O regimes. */

FD_FN_UNUSED static int /* Work around -Winline */
fd_io_buffered_istream_read( fd_io_buffered_istream_t * in,
                             void *                     dst,
                             ulong                      dst_sz ) {
  /* We destructure in to avoid pointer escapes that might inhibit
     optimizations of other in inlines. */
  ulong rbuf_lo    = in->rbuf_lo;
  ulong rbuf_ready = in->rbuf_ready;
  int err = fd_io_buffered_read( in->fd, dst, dst_sz, in->rbuf, in->rbuf_sz, &rbuf_lo, &rbuf_ready );
  in->rbuf_lo    = rbuf_lo;
  in->rbuf_ready = rbuf_ready;
  return err;
}

/* fd_io_buffered_istream_skip skips skip_sz bytes from in.  Assumes in
   is initialized.  Returns 0 on success and non-zero on failure.
   Failure interpretation is the same as fd_io_buffered_read.  On a
   failure, in and the underlying file descriptor should be considered
   to be in a failed state (e.g. the only valid thing to do to in is
   fini and the only valid thing to do to fd is close).

   If the fd underlying in is seekable (e.g. a file), this will be very
   fast.  If not (e.g. fd is pipe / socket / etc), this can block the
   caller until skip_sz bytes have arrived or an I/O error is detected.

   IMPORTANT!  See note in fd_io_buffered_istream_read above about the
   impact of this on file pointer alignment. */

static inline int
fd_io_buffered_istream_skip( fd_io_buffered_istream_t * in,
                             ulong                      skip_sz ) {
  /* We destructure in to avoid pointer escapes that might inhibit
     optimizations of other in inlines. */
  ulong rbuf_lo    = in->rbuf_lo;
  ulong rbuf_ready = in->rbuf_ready;
  int err = fd_io_buffered_skip( in->fd, skip_sz, in->rbuf, in->rbuf_sz, &rbuf_lo, &rbuf_ready );
  in->rbuf_lo    = rbuf_lo;
  in->rbuf_ready = rbuf_ready;
  return err;
}

/* fd_io_buffered_istream_peek returns a pointer in the caller's address
   space to the first byte that has been read but not yet consumed.
   Assumes in is initialized.  The returned pointer can have arbitrary
   alignment and the returned pointer lifetime is until the next read,
   fetch, or fini. */

FD_FN_PURE static inline void const *
fd_io_buffered_istream_peek( fd_io_buffered_istream_t * in ) {
  return in->rbuf + in->rbuf_lo;
}

/* fd_io_buffered_istream_peek_sz returns the number of bytes that have
   been read but not yet consumed.  Assumes in is initialized.  Returned
   value will be in [0,rbuf_sz] and will be valid until the next read,
   fetch, seek or fini. */

FD_FN_PURE static inline ulong
fd_io_buffered_istream_peek_sz( fd_io_buffered_istream_t * in ) {
  return in->rbuf_ready;
}

/* fd_io_buffered_istream_seek consumes sz buffered bytes from in.
   Assumes in is initialized and that sz is at most peek_sz. */

static inline void
fd_io_buffered_istream_seek( fd_io_buffered_istream_t * in,
                             ulong                      sz ) {
  in->rbuf_lo    += sz;
  in->rbuf_ready -= sz;
}

/* fd_io_buffered_istream_fetch tries to fill up the stream's read
   buffer with as many unconsumed bytes as possible.  Assumes in is
   initialized.  Returns 0 on success (rbuf is filled to rbuf_sz with
   unconsumed data) and non-zero on failure (see below for
   interpretation).  On failure, in and the underlying file descriptor
   should be considered to be in a failed state (e.g. the only valid
   thing to do out on is fini and the only valid thing to do on fd is
   close).  That is:

     int err = fd_io_buffered_istream_fetch( in );
     if(      FD_LIKELY( err==0      ) ) ... success,     peek_sz() updated to at most rbuf_sz
     else if( FD_LIKELY( err< 0      ) ) ... end-of-file, peek_sz() updated to at most rbuf_sz and is num unconsumed bytes to EOF
     else if( FD_LIKELY( err==EAGAIN ) ) ... try again,   peek_sz() unchanged, only possible if fd is non-blocking
     else                                ... I/O error,   peek_sz() unchanged,
                                         ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                                         ... in and fd should be considered failed

   IMPORTANT!  See note in fd_io_buffered_istream_read above about the
   impact of fetch on file pointer alignment. */

FD_FN_UNUSED static int /* Work around -Winline */
fd_io_buffered_istream_fetch( fd_io_buffered_istream_t * in ) {
  uchar * rbuf       = in->rbuf;
  ulong   rbuf_sz    = in->rbuf_sz;
  ulong   rbuf_lo    = in->rbuf_lo;
  ulong   rbuf_ready = in->rbuf_ready;
  if( FD_UNLIKELY( rbuf_ready>=rbuf_sz ) ) return 0; /* buffer already full */
  if( FD_LIKELY( (!!rbuf_ready) & (!!rbuf_lo) ) ) memmove( rbuf, rbuf+rbuf_lo, rbuf_ready ); /* Move unconsumed to beginning */
  ulong   rsz;
  int     err = fd_io_read( in->fd, rbuf+rbuf_ready, 0UL, rbuf_sz-rbuf_ready, &rsz );
  in->rbuf_lo    = 0UL;
  in->rbuf_ready = rbuf_ready + rsz;
  return err;
}

/* fd_io_buffered_ostream_init initializes out to do buffered writes to
   the given file descriptor.  out is an unused location that should
   hold the stream state, fd is an open normal-ish file descriptor to
   buffer, wbuf points to the first byte in the caller's address space
   to an unused wbuf_sz size memory region to use for the buffering
   (assumes wbuf is non-NULL with arbitrary alignment and wbuf_sz is
   positive).  Returns out and on return out will be initialized.  On
   return out will have ownership of fd and wbuf. */

static inline fd_io_buffered_ostream_t *
fd_io_buffered_ostream_init( fd_io_buffered_ostream_t * out,
                             int                        fd,
                             void *                     wbuf,
                             ulong                      wbuf_sz ) {
  out->fd        = fd;
  out->wbuf      = (uchar *)wbuf;
  out->wbuf_sz   = wbuf_sz;
  out->wbuf_used = 0UL;
  return out;
}

/* fd_io_buffered_ostream_{fd,wbuf,wbuf_sz} return the corresponding
   value used to initialize out.  Assumes out is initialized. */

FD_FN_PURE static inline int    fd_io_buffered_ostream_fd     ( fd_io_buffered_ostream_t const * out ) { return out->fd;      }
FD_FN_PURE static inline void * fd_io_buffered_ostream_wbuf   ( fd_io_buffered_ostream_t const * out ) { return out->wbuf;    }
FD_FN_PURE static inline ulong  fd_io_buffered_ostream_wbuf_sz( fd_io_buffered_ostream_t const * out ) { return out->wbuf_sz; }

/* fd_io_buffered_ostream_fini finalizes a buffered output stream.
   Assumes out is initialized.  On return out will no longer be
   initialized and the caller will have ownership of the underlying fd
   and wbuf.

   IMPORTANT!  THIS WILL NOT DO ANY FINAL FLUSH OF BUFFERED BYTES.  IT
   IS THE CALLER'S RESPONSIBILITY TO DO THIS IN THE NORMAL FINI CASE. */

static inline void
fd_io_buffered_ostream_fini( fd_io_buffered_ostream_t * out ) {
  (void)out;
}

/* fd_io_buffered_ostream_write writes src_sz bytes from src to the
   stream, temporarily buffering zero or more bytes as convenient.
   Assume out is initialized.  src / src_sz have the same meaning /
   restrictions as fd_io_buffered_write.  Returns 0 on success and
   non-zero on failure.  Failure interpretation is the same as
   fd_io_buffered_write.  On failure, out and the underlying file
   descriptor should be considered to be in a failed state (e.g.  the
   only valid thing to do to out is fini and the only valid thing to do
   to fd is close).

   IMPORTANT!  If fd_io_buffered_ostream_flush is only used to do a
   final flush before fini, all the writes to the underlying stream will
   always be at multiples of wbuf_sz offset from the initial file offset
   when the out was initialized and all the write sizes (except
   potentially the final flush) will be a multiple of wbuf_sz in size.
   This can be beneficial in various high performance I/O regimes. */

static inline int
fd_io_buffered_ostream_write( fd_io_buffered_ostream_t * out,
                              void const *               src,
                              ulong                      src_sz ) {
  /* We destructure out to avoid pointer escapes that might inhibit
     optimizations of other inlines that operate on out. */
  ulong wsz = out->wbuf_used;
  int   err = fd_io_buffered_write( out->fd, src, src_sz, out->wbuf, out->wbuf_sz, &wsz );
  out->wbuf_used = wsz;
  return err;
}

/* fd_io_buffered_ostream_peek returns a pointer in the caller's address
   space where the caller can prepare bytes to be streamed out.  Assumes
   out is initialized.  The returned pointer can have arbitrary
   alignment and the returned pointer lifetime is until the next write,
   flush, or fini. */

FD_FN_PURE static inline void *
fd_io_buffered_ostream_peek( fd_io_buffered_ostream_t * out ) {
  return out->wbuf + out->wbuf_used;
}

/* fd_io_buffered_istream_peek_sz returns the number of bytes available
   at the peek location.  Assumes out is initialized.  Returned value
   will be in [0,wbuf_sz] and will be valid until the next write, fetch,
   seek or fini. */

FD_FN_PURE static inline ulong
fd_io_buffered_ostream_peek_sz( fd_io_buffered_ostream_t * out ) {
  return out->wbuf_sz - out->wbuf_used;
}

/* fd_io_buffered_istream_seek commits the next sz unused write buffer
   bytes to be streamed out.  Assumes out is initialized and that sz is
   at most peek_sz. */

static inline void
fd_io_buffered_ostream_seek( fd_io_buffered_ostream_t * out,
                             ulong                      sz ) {
  out->wbuf_used += sz;
}

/* fd_io_buffered_ostream_flush writes any buffered bytes in the stream's
   write buffer to the underlying file descriptor.  Assume out is
   initialized.  Returns 0 on success (all buffered bytes written to fd)
   and non-zero on failure (see below for interpretation).  In both
   cases, the write buffer will be empty on return.  On failure, out and
   the underlying file descriptor should be considered to be in a failed
   state (e.g. the only valid thing to do to out is fini and the only
   valid thing to do to fd is close).

     int err = fd_io_buffered_ostream_flush( out );
     if( FD_LIKELY( err==0 ) ) ... success,   write buffer empty
     else                      ... I/O error, write buffer empty
                               ... err is strerror compat, err is neither EAGAIN nor EWOULDBLOCK
                               ... in and fd should be considered failed

   IMPORTANT!  See note in fd_io_buffered_ostream_write below about the
   impact of doing this outside a final flush. */

FD_FN_UNUSED static int /* Work around -Winline */
fd_io_buffered_ostream_flush( fd_io_buffered_ostream_t * out ) {
  ulong wbuf_used = out->wbuf_used;
  if( FD_UNLIKELY( !wbuf_used ) ) return 0; /* optimize for lots of tiny writes */
  out->wbuf_used = 0UL;
  ulong wsz;
  return fd_io_write( out->fd, out->wbuf, wbuf_used, wbuf_used, &wsz );
}

/* Misc APIs */

/* fd_io_strerror converts an fd_io error code (i.e. negative ->
   end-of-file, 0 -> success, positive -> strerror compatible) into a
   human readable cstr.  Unlike strerror, the lifetime of the returned
   pointer is infinite and the call itself is thread safe.  The
   returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_io_strerror( int err );

/* fd_io_strsignal converts a signal code (like returned by WTERMSIG)
   into a human readable cstr.  Unlike strsignal, the lifetime of the
   returned pointer is infinite and the call itself is thread safe.
   Unlike the glibc strsignal implementation in particular, it does
   not call `brk(3)` or `futex(2)` internally.  The returned pointer
   is always to a non-NULL cstr. */
FD_FN_CONST char const *
fd_io_strsignal( int err );

/* TODO: ASYNC IO APIS */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_h */
