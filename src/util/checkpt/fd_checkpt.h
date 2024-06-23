#ifndef HEADER_fd_src_util_checkpt_fd_checkpt_h
#define HEADER_fd_src_util_checkpt_fd_checkpt_h

/* APIs for fast parallel compressed checkpoint and restore.  Concepts:

   - A checkpoint contains of zero or more frames.

   - Each frame resides in a disjoint contiguous sequence of bytes in
     the checkpoint and contains a sequence of zero of more data
     buffers.

   - Data buffers can have (up to physical limitation) arbitrary
     variable byte size.

   - A frame has a style that specifies how data buffers have been
     encoded into it.

   - Buffers in a RAW frame are stored verbatim with no gaps.  As such,
     the space needed for a raw frame and the location of buffers in a
     raw frame can computed exactly up front.

   - Buffers in a LZ4 frame are stored via LZ4 streaming compression.  A
     worst case upper bound for the space needed for a LZ4 frame can be
     computed up front, roughly:

       (256/255) total_sz_all_buffers + 19 buffer_count.

     The location of buffers in LZ4 frame is not practically computable
     in advance and decompression of a buffer in a frame depends on
     previous buffers in that frame.

   - Checkpoints can be read and written in a streaming IO mode or in a
     memory IO mode with the exact same APIs (i.e. no changes to the
     calling code outside of specifying the mode when starting a
     checkpoint or a restore).  The checkpoint and restore processes
     will produce bit-level identical results regardless of mode.

   - Frames are independent such that different frames can be generated
     in parallel.  Each frame generated will be bit-level identical
     regardless how generation is distributed over threads.

   - Similarly, frames can restored in parallel.  The restored results
     will be bit-level identical regardles how restoration is
     distributed over threads.

   - As such, arbitrary streaming/mmio serial/parallel operation is fine
     (e.g. have a single thread write a checkpoint file with streaming
     I/O and then use multiple threads to restore from that checkpoint
     file with memory mapped I/O). */

#include "../log/fd_log.h"

/* FD_CHECKPT_SUCCESS / FD_CHECKPT_ERR_* are return values from various
   fd_checkpt APIs.  SUCCESS is zero and ERR_* are negative integers. */

#define FD_CHECKPT_SUCCESS   (0)  /* operation was successful */
#define FD_CHECKPT_ERR_INVAL (-1) /* operation failed because bad input arguments */
#define FD_CHECKPT_ERR_UNSUP (-2) /* operation failed because it is unsupported on this target */
#define FD_CHECKPT_ERR_IO    (-3) /* operation failed because an I/O error occurred */
#define FD_CHECKPT_ERR_COMP  (-4) /* operation failed because a compressor/decompressor error occurred */

/* FD_CHECKPT_FRAME_STYLE_* specify a checkpoint frame style.  These are
   positive integers. */

#define FD_CHECKPT_FRAME_STYLE_RAW (1) /* uncompressed   frame */
#define FD_CHECKPT_FRAME_STYLE_LZ4 (2) /* lz4 compressed frame */

#define FD_CHECKPT_FRAME_STYLE_DEFAULT FD_CHECKPT_FRAME_STYLE_RAW

/* FD_CHECKPT_WBUF_MIN is the minimum write buffer size needed by a
   fd_checkpt_t in streaming mode.  Must be at least 65813 ~
     FD_CHECKPT_PRIVATE_CSZ_MAX( FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX ) */

#define FD_CHECKPT_WBUF_MIN (69632UL) /* 68 KiB */

/* FD_CHECKPT_{ALIGN,FOOTPRINT} give the required {alignment,footprint}
   of a memory region suitable for use as a fd_checkpt_t. */

#define FD_CHECKPT_ALIGN     alignof( fd_checkpt_t )
#define FD_CHECKPT_FOOTPRINT sizeof(  fd_checkpt_t )

/* A fd_checkpt_t is a semi-opaque handle for an in-progress checkpoint
   (a stack or global declaration of an fd_checkpt_t is sufficient to
   get the correct alignment and footprint). */

struct fd_checkpt_private;
typedef struct fd_checkpt_private fd_checkpt_t;

/* FD_RESTORE_RBUF_MIN is the minimum read buffer size needed by a
   fd_restore_t in streaming mode.  Must be at least
   FD_CHECKPT_WBUF_MIN. */

#define FD_RESTORE_RBUF_MIN FD_CHECKPT_WBUF_MIN

/* FD_RESTORE_{ALIGN,FOOTPRINT} give the required {alignment,footprint}
   of a memory region suitable for use as a fd_restore_t. */

#define FD_RESTORE_ALIGN     alignof( fd_restore_t )
#define FD_RESTORE_FOOTPRINT sizeof(  fd_restore_t )

/* A fd_restore_t is a semi-opaque handle of an in-progress restore (a
   stack or global declaration of an fd_restore_t is sufficient to get
   the correct alignment and footprint). */

struct fd_restore_private;
typedef struct fd_restore_private fd_restore_t;

/* Internal use only **************************************************/

/* These are exposed to facilitate things like stack declaration */

/* FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX is the maximum amount of checkpt
   data fed into the underlying compressor at a time.  Should be much
   less than LZ4_MAX_INPUT_SIZE (and probably much less than 2^24-1).
   64 KiB is recommended. */

#define FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX (65536UL)

/* FD_CHECKPT_PRIVATE_CSZ_MAX returns a reasonably tight upper bound to
   the number of compressed output bytes generated given usz
   uncompressed input bytes.  Assumes usz is safe against multiple
   evaluation and usz<=FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX.  (This is the
   same as LZ4_COMPRESSBOUND plus 3 extra bytes for checkpt related
   metadata plus ulong typing usz and the usz limit.) */

#define FD_CHECKPT_PRIVATE_CSZ_MAX(usz) ((usz) + ((usz)/255UL) + 19UL)

FD_STATIC_ASSERT( FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX <= (1UL<<30), adjust_comp_limits );
FD_STATIC_ASSERT( FD_CHECKPT_WBUF_MIN >= FD_CHECKPT_PRIVATE_CSZ_MAX( FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX ), adjust_buf_limits );
FD_STATIC_ASSERT( FD_RESTORE_RBUF_MIN >= FD_CHECKPT_WBUF_MIN, adjust_buf_limits );

/* FD_CHECKPT_PRIVATE_GBUF_THRESH is byte size at which checkpt buffer
   is considered too large for small buffer checkpt gather
   optimizations.  Should be at most FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX.
   Set to 0 to disable checkpt small gather optimization. */

#define FD_CHECKPT_PRIVATE_GBUF_THRESH FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX

/* FD_CHECKPT_PRIVATE_GBUF_SZ is the size of the checkpt gather buffer.
   Must be at least 2*THRESH + 65536 - 3 (the 64KiB is from LZ4). */

#define FD_CHECKPT_PRIVATE_GBUF_SZ (2UL*FD_CHECKPT_PRIVATE_GBUF_THRESH + 65536UL)

FD_STATIC_ASSERT( FD_CHECKPT_PRIVATE_GBUF_THRESH <= FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX,             adjust_gbuf_limits );
FD_STATIC_ASSERT( FD_CHECKPT_PRIVATE_GBUF_SZ     >= 2UL*FD_CHECKPT_PRIVATE_GBUF_THRESH + 65533UL, adjust_gbuf_limits );

/* FD_RESTORE_PRIVATE_SBUF_{THRESH,SZ} similarly give the configuration
   for small buffer restore scatter optimizations.  These currently need
   to match the gather configuration. */

#define FD_RESTORE_PRIVATE_SBUF_THRESH FD_CHECKPT_PRIVATE_GBUF_THRESH
#define FD_RESTORE_PRIVATE_SBUF_SZ     FD_CHECKPT_PRIVATE_GBUF_SZ

/* fd_checkpt_t internals */

struct fd_checkpt_private_wbuf { /* very similar to fd_io_buffered_ostream */
  uchar * mem;  /* Buffer of compressed bytes not yet written to fd, byte indexed [0,wbuf_sz) */
  ulong   sz;   /* Buffer size in bytes, >=FD_CHECKPT_WBUF_MIN */
  ulong   used; /* Buffer bytes [0,wbuf_used) are not yet written to fd,
                   buffer bytes [wbuf_used,wbuf_sz) are free */
};

typedef struct fd_checkpt_private_wbuf fd_checkpt_private_wbuf_t;

struct fd_checkpt_private_mmio {
  uchar * mem; /* Checkpoint memory region */
  ulong   sz;  /* Checkpoint memory region byte size */
};

typedef struct fd_checkpt_private_mmio fd_checkpt_private_mmio_t;

struct fd_checkpt_private {
  int    fd;          /* (stream) File descriptor for the checkpt (>=0), (mmio) -1 */
  int    frame_style; /* FD_CHECKPT_FRAME_STYLE_* (>0), 0: not in frame (valid), -1: not in frame (failed) */
  void * lz4;         /* Handle of the underlying compressor */
  ulong  gbuf_cursor; /* Cursor for small buffer gather optimizations, in [0,FD_CHECKPT_PRIVATE_GBUF_SZ] */
  ulong  off;         /* Offset of the next byte to write (relative to the checkpoint first byte), in [0,mmio_sz) in mmio mode */
  union {
    fd_checkpt_private_wbuf_t wbuf; /* used in streaming mode */
    fd_checkpt_private_mmio_t mmio; /* used in mmio mode */
  };
  uchar gbuf[ FD_RESTORE_PRIVATE_SBUF_SZ ]; /* gather optimization buffer */
};

/* fd_restore_t internals */

struct fd_restore_private_rbuf { /* very similar to fd_io_buffered_istream */
  uchar * mem;  /* Buffer of compressed bytes read from fd, byte indexed [0,rbuf_sz) */
  ulong  sz;    /* Buffer size in bytes, >=FD_RESTORE_RBUF_MIN */
  ulong  lo;    /* Buffer bytes [0,rbuf_lo) have been read and restored */
  ulong  ready; /* Number of compressed bytes that haven't been processed, 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz */
};

typedef struct fd_restore_private_rbuf fd_restore_private_rbuf_t;

struct fd_restore_private_mmio {
  uchar const * mem; /* Checkpoint memory region */
  ulong         sz;  /* Checkpoint memory region size in bytes */
  ulong         off; /* Offset of next byte to process relative to mmio, in [0,mmio_sz) */
};

typedef struct fd_restore_private_mmio fd_restore_private_mmio_t;

struct fd_restore_private {
  int    fd;          /* (stream) File descriptor for the restore (>=0), (mmio) -1 */
  int    frame_style; /* FD_CHECKPT_FRAME_STYLE_* (>0), 0: not in frame (valid), -1: not in frame (failed) */
  void * lz4;         /* Handle of the underlying decompressor used */
  ulong  sbuf_cursor; /* Cursor for small buffer scatter optimizations, in [0,FD_RESTORE_PRIVATE_SBUF_SZ] */
  union {
    fd_restore_private_rbuf_t rbuf; /* used in streaming mode */
    fd_restore_private_mmio_t mmio; /* used in mmio mode */
  };
  uchar sbuf[ FD_RESTORE_PRIVATE_SBUF_SZ ]; /* scatter optimization buffer */
};

FD_PROTOTYPES_BEGIN

/* fd_{checkpt,restore}_private_is_mmio returns 0/1 if in streaming/mmio
   mode.  Assumes {checkpt,restore} is valid. */

FD_FN_PURE static inline int fd_checkpt_private_is_mmio( fd_checkpt_t const * checkpt ) { return checkpt->fd<0; }
FD_FN_PURE static inline int fd_restore_private_is_mmio( fd_restore_t const * restore ) { return restore->fd<0; }

/* fd_checkpt_private_{can_open,in_frame} returns 1 if {a frame can be
   opened,the checkpt is in a frame} and 0 otherwise.  A failed checkpt
   is not in a frame but cannot open a new frame.  Assumes checkpt is
   valid.  Similarly for restore. */

FD_FN_PURE static inline int fd_checkpt_private_can_open( fd_checkpt_t const * checkpt ) { return !checkpt->frame_style; }
FD_FN_PURE static inline int fd_restore_private_can_open( fd_restore_t const * restore ) { return !restore->frame_style; }

FD_FN_PURE static inline int fd_checkpt_private_in_frame( fd_checkpt_t const * checkpt ) { return checkpt->frame_style>0; }
FD_FN_PURE static inline int fd_restore_private_in_frame( fd_restore_t const * restore ) { return restore->frame_style>0; }

FD_PROTOTYPES_END

/* End internal use only **********************************************/

FD_PROTOTYPES_BEGIN

/* Checkpt APIs *******************************************************/

/* fd_checkpt_init_stream formats a memory region, mem, with suitable
   alignment and footprint into a fd_checkpt_t (a pointer to a stack
   declared fd_checkpt_t is fine).  fd is an open normal-ish file
   descriptor where the checkpoint should be streamed out.  wbuf points
   to the first byte in the caller's address space to an unused wbuf_sz
   byte size memory region to use for write buffering.  wbuf_sz should
   be at least FD_CHECKPT_WBUF_MIN.

   On success, returns mem formatted as a fd_checkpt_t in streaming
   mode.  On return, the fd_checkpt_t will be valid, not in a frame and
   will have ownership of mem, fd, and wbuf.

   On failure, returns NULL (logs details).  No ownership changed. */

fd_checkpt_t *
fd_checkpt_init_stream( void * mem,
                        int    fd,
                        void * wbuf,
                        ulong  wbuf_sz );

/* fd_checkpt_init_mmio is the same as fd_checkpt_init_stream but
   checkpoints frames into a mmio_sz byte sized memory region whose
   first byte in the caller's the local address space is pointed to by
   mmio. */

fd_checkpt_t *
fd_checkpt_init_mmio( void * mem,
                      void * mmio,
                      ulong  mmio_sz );

/* fd_checkpt_fini finishes a checkpoint.  checkpt should be valid and
   not in a frame.

   On success, returns mem.  On return, checkpt is no longer valid and
   the caller will have ownership of mem, fd and wbuf (streaming mode)
   or mem and mmio (mmio mode).

   On failure, returns NULL (logs details).  Reasons for failure include
   NULL checkpt and checkpt in a frame.  The checkpt (and underlying fd
   in streaming mode) should be considered failed (i.e. checkpt no
   longer has any interest in checkpointed data and the user should only
   fini checkpt, close fd in streaming mode and discard the failed
   checkpoint). */

void *
fd_checkpt_fini( fd_checkpt_t * checkpt );

/* fd_checkpt_frame_open_advanced opens a new frame.  Different frames
   in a checkpoint can be restored in parallel.  frame_style is a
   FD_CHECKPT_FRAME_STYLE_* that specifies the style of frame to output
   (0 indicates to use FD_CHECKPT_FRAME_STYLE_DEFAULT).  checkpt should
   be valid and openable (not currently in a frame or failed).

   On success, returns FD_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of this frame from the beginning of the
   checkpoint.  This is to allow parallel restore threads to jump to
   frames they are assigned to restore.  Retains no interest in _off.

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).
   *_off will be untouched.  Retains no interest in _off.  Reasons for
   failure include INVAL (NULL checkpt, in a frame, failed), UNSUP
   (unsupported frame style on this target), IO (an i/o error) and COMP
   (a compressor error).  The checkpt (and underlying fd in streaming
   mode) should be considered failed (i.e. the checkpt no longer has
   any interest in checkpointed data and the user should only fini
   checkpt, close fd in streaming mode and discard the failed
   checkpoint).

   IMPORTANT SAFETY TIP!  The returned offset is relative to the start
   of the _checkpoint_, _not_ the start of the _file_.  These are often
   the same but do not have to be (e.g. writing a checkpoint to an
   unseekable file descriptor like stdout, the caller has already
   written other data to the file descriptor before starting the
   checkpoint, etc).

   IMPORTANT SAFETY TIP!  Compression ratios for compressed frames can
   optimized by putting similar items into the same frame and then
   putting more similar items near each other sequentially.

   fd_checkpt_frame_open is a convenience for when the frame offset
   isn't needed (makes API exactly symmetric with fd_restore). */

int
fd_checkpt_frame_open_advanced( fd_checkpt_t * checkpt,
                                int            frame_style,
                                ulong *        _off );

static inline int
fd_checkpt_frame_open( fd_checkpt_t * checkpt,
                       int            frame_style ) {
  ulong off;
  return fd_checkpt_frame_open_advanced( checkpt,frame_style, &off );
}

/* fd_checkpt_frame_close_advanced closes the current frame.  checkpt
   should be valid and in a frame.

   On success, returns FD_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of one past the last byte of the just closed
   frame.  That is, [off_open,off_close) specify the range bytes
   relative to the start of the checkpoint used by this frame and
   off_close-off_open is the frame byte size.  This is to facilitate
   parallel checkpoint writing and then concatentating results from
   different threads into a compact checkpoint.  checkpt will no longer
   have any interest in checkpointed data or in _off.

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).  On
   return, *_off will be untouched and checkpoint will have no inteest
   in _off.  Reasons for failure include INVAL (NULL checkpt, not in a
   frame), IO (write failed, too many bytes written) and COMP (a
   compressor error).  The checkpt (and underlying fd in streaming mode)
   should be considered failed (i.e. the checkpt no longer has any
   interest in checkpointed data and the user should only fini checkpt,
   close fd in streaming mode and discard the failed checkpoint).

   fd_checkpt_frame_close is a convenience for when the frame offset
   isn't needed. */

int
fd_checkpt_frame_close_advanced( fd_checkpt_t * checkpt,
                                 ulong *        _off );

static inline int
fd_checkpt_frame_close( fd_checkpt_t * checkpt ) {
  ulong off;
  return fd_checkpt_frame_close_advanced( checkpt, &off );
}

/* fd_checkpt_buf checkpoints the sz byte memory region whose first byte
   in the caller's local address space is pointed to by buf.  checkpt
   should be valid and in a frame.  sz==0 is fine (and buf==NULL if
   sz==0 is also fine).

   On success, returns FD_CHECKPT_SUCCESS (0).  IMPORTANT SAFETY TIP!
   checkpt retains an interest in buf until the frame is closed (e.g.
   buf should continue to exist unchanged until the frame is closed).
   AMONG OTHER THINGS, THIS MEANS IT IS UNSAFE TO GATHER DATA INTO A
   TEMP BUFFER, CHECKPT THE TEMP BUFFER AND THEN FREE / REUSE THAT TEMP
   BUFFER BEFORE THE FRAME IS CLOSED!

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL checkpt, not in a frame, NULL
   buf with a non-zero sz), IO (write failed, too many bytes written)
   and COMP (compressor error).  The checkpt (and underlying fd in
   streaming mode) should be considered failed (i.e. should only fini
   checkpt, close fd in streaming mode and discard the failed
   checkpoint). */

int
fd_checkpt_buf( fd_checkpt_t * checkpt,
                void const *   buf,
                ulong          sz );

/* Restore APIs *******************************************************/

/* fd_restore_init_stream formats a memory region, mem, with suitable
   alignment and footprint into a fd_restore_t in streaming mode (a
   pointer to a stack declared fd_restore_t is fine).  fd is an open
   normal-ish file descriptor positioned at the start of the first
   checkpoint frame to read.  rbuf points to the first byte in the
   caller's address space of an unused rbuf_sz byte size memory region
   to use for read buffering.  rbuf_sz should be at least
   FD_RESTORE_RBUF_MIN (it does _not_ need to match the wbuf_sz used to
   make the checkpoint).

   On success, returns mem formatted as a fd_restore_t.  On return, the
   fd_restore_t will be valid, not in a frame and will have ownership of
   mem, fd, and rbuf.

   On failure, returns NULL (logs details).  No ownership changed. */

fd_restore_t *
fd_restore_init_stream( void * mem,
                        int    fd,
                        void * rbuf,
                        ulong  rbuf_sz );

/* fd_restore_init_mmio is the same as fd_restore_init_stream but the
   frames to restore have been memory mapped into the mmio_sz byte
   memory region whose first byte in the caller's the local address
   space is pointed to by mmio. */

fd_restore_t *
fd_restore_init_mmio( void *       mem,
                      void const * mmio,
                      ulong        mmio_sz );

/* fd_restore_fini finishes restoring from a checkpoint.  restore should
   be valid and not in a frame.

   On success, returns mem.  On return, restore is no longer valid and
   the caller will have ownership of mem, fd and rbuf (streaming mode)
   or mem and mmio (mmio mode).

   On failure, returns NULL (logs details).  Reasons for failure include
   NULL restore and restore in a frame.  The restore (and underlying fd
   in streaming mode) should be considered failed (i.e. the restore no
   longer has any interest in restored data and the user should only
   fini restore and close fd in streaming mode). */

void *
fd_restore_fini( fd_restore_t * restore );

/* fd_restore_frame_open opens a new checkpoint frame.  Different frames
   in a checkpoint can be restored in parallel.  frame_style is a
   FD_CHECKPT_FRAME_STYLE_* that specifies the style of frame to read
   (0 indicates to use FD_CHECKPT_FRAME_STYLE_DEFAULT).  restore should
   be valid and not currently in a frame.

   On success, returns FD_CHECKPT_SUCCESS (0).

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, in a frame, failed),
   UNSUP (unsupported frame style on this target), IO (an i/o error) and
   COMP (a decompressor error).  The restore (and underlying fd in
   streaming mode) should be considered failed (i.e. the restore no
   longer has any interest in restored data and the user should only
   fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  frame_style should match the frame_style used
   to when the checkpoint was written.

   IMPORTANT SAFETY TIP!  The sequence of restore_frame_open /
   restore_buf / restore_frame_close calls should _exactly_ match the
   sequence of checkpt_frame_open / checkpt_buf / checkpt_frame_close
   used when the frame was written. */

int
fd_restore_frame_open( fd_restore_t * restore,
                       int            frame_style );

/* fd_restore_frame_close closes the current frame.  restore should be
   valid and in a frame.

   On success, returns FD_CHECKPT_SUCCESS (0).  The restore will no
   longer have any interest in restored data.

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not in a frame), IO
   (an i/o error) and COMP (a decompressor error).  The restore (and
   underlying fd in streaming mode) should be considered failed (i.e.
   the restore no longer has any interest in restored data and the user
   should only fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The sequence of restore_frame_open /
   restore_buf / restore_frame_close calls should _exactly_ match the
   sequence of checkpt_frame_open / checkpt_buf / checkpt_frame_close
   used when the frame was created. */

int
fd_restore_frame_close( fd_restore_t * restore );

/* fd_restore_buf restores sz bytes to the memory region whose first
   byte in the caller's local address space is pointed to by buf.
   restore should be valid and in a frame.  sz==0 is fine (and buf==NULL
   if sz==0 is also fine).

   On success, returns FD_CHECKPT_SUCCESS (0).  On return, buf will
   contain the restored data (FIXME: consider not guaranteeing
   availability of the restored buf until the frame is closed).
   IMPORTANT SAFETY TIP!  restore retains an interest in buf until the
   frame is closed (e.g. buf should continue to exist unchanged until
   the frame is closed).  AMONG OTHER THINGS, THIS IMPLIES RESTORE
   MEMORY REGIONS SHOULD NOT OVERLAP AND THAT IT IS UNSAFE TO RESTORE TO
   A TEMP BUFFER, SCATTER DATA FROM THE TEMP BUFFER AND THEN FREE /
   REUSE THAT TEMP BUFFER BEFORE THE FRAME IS CLOSED!

   On failure, logs details and returns a FD_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not in a frame, NULL
   buf with a non-zero sz), IO (read failed, too many bytes read) and
   COMP (a decompressor error).  The restore (and underlying fd in
   streaming mode) should be considered failed (i.e. the restore no
   longer has any interest in restored data and the user should only
   fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The sequence of restore_frame_open /
   restore_buf / restore_frame_close calls should _exactly_ match the
   sequence of checkpt_frame_open / checkpt_buf / checkpt_frame_close
   used when the frame was created. */

int
fd_restore_buf( fd_restore_t * restore,
                void *         buf,
                ulong          sz );

/* Misc APIs **********************************************************/

/* fd_checkpt_strerror converts an FD_CHECKPT_SUCCESS / FD_CHECKPT_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

char const *
fd_checkpt_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_checkpt_fd_checkpt_h */
