#ifndef HEADER_fd_src_ballet_zstd_fd_zstd_h
#define HEADER_fd_src_ballet_zstd_fd_zstd_h

/* fd_zstd provides APIs for Zstandard compressed streams, such as .zst
   files.  Currently uses libzstd in static mode under the hood.

   ### Format

   The Zstandard compression format is documented here:
   https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md

   Zstandard streams are the concatenation of one or more frames.
   fd_zstd only handles frames containing compressed data.

   Frames are not interdependent which usually allows for stateless
   processing between frames.  Dictionary and prefixes are exceptions
   which may add dependencies to external data.  fd_zstd currently does
   not support those.

   ### Memory management

   fd_zstd promises to not do any dynamic heap allocations nor syscalls.

   Each fd_zstd_{d,c}stream_t object is backed by a contiguous memory
   region which is allocated and managed by the caller.  There are few
   restrictions on the nature of this memory region (may be backed by
   a workspace, scratch, bss, or even the stack).  However, fd_zstd
   objects may not be relocated or shared across address spaces.

   The footprint of fd_zstd_dstream_t (decompression) depends on the
   "window size" (relates to compression level and independent of data
   size).  Each Zstandard frame requires a particular window size to
   decompress.  If this parameter is unknown, it can be recovered via
   fd_zstd_peek_window_sz.  fd_zstd gracefully fails when attempting to
   decompress a frame that exceeds the max window size that the
   fd_zstd_dctx_t was initialized with.

   The footprint of fd_zstd_cstream_t (compression) depends on the
   compression level.

   ### Possible improvements

   libzstd's single-shot decompression mode requires much less scratch
   data (only 128 KiB instead of 128 MiB).  However, it requires the
   input and output buffers to fit the entire compressed/decompressed
   frame.  The Solana protocol does not properly bound max decompressed
   frame size, so using streaming mode is safer for now. */

#if FD_HAS_ZSTD

#include "../fd_ballet_base.h"

/* FD_ZSTD_MAX_HDR_SZ is the amount of bytes required to fit any
   possible frame header.  (Including both the magic number and the
   frame itself) */

#define FD_ZSTD_MAX_HDR_SZ (18UL)

/* Decompress API *****************************************************/

/* fd_zstd_dstream_t provides streaming decompression for Zstandard
   frames.  Handles one frame at a time. */

struct fd_zstd_dstream;
typedef struct fd_zstd_dstream fd_zstd_dstream_t;

struct fd_zstd_peek {
  ulong window_sz;
  ulong frame_content_sz;  /* ULONG_MAX if unknown */
  int   frame_is_skippable;
};
typedef struct fd_zstd_peek fd_zstd_peek_t;

FD_PROTOTYPES_BEGIN

/* fd_zstd_peek peeks a frame header.  buf points to a fragment
   containing the first FD_ZSTD_MAX_HDR_SZ bytes of the frame (or less
   if EOF reached).  bufsz is the size of that fragment.  peek is
   populated with the decoded data.  Caller should zero-initialize peek
   for forward compatibility.  Returns peek on success.  On failure,
   returns NULL.  Reasons for failure include insufficient bufsz or
   decode error. */

fd_zstd_peek_t *
fd_zstd_peek( fd_zstd_peek_t * peek,
              void const *     buf,
              ulong            bufsz );

/* fd_zstd_dstream_{align,footprint} return the parameters of the
   memory region backing a fd_zstd_dstream_t.  max_window_sz is the
   largest window size that this object is able to handle. */

ulong
fd_zstd_dstream_align( void );

ulong
fd_zstd_dstream_footprint( ulong max_window_sz );

/* fd_zstd_dstream_new creates a new dstream object backed by the memory
   region at mem.  mem matches align/footprint requirements for the
   given max_window_sz.  Returns a handle to the newly created dstream
   object on success (not just a simple cast of mem).  The dstream
   expects a new frame on return.  On failure, returns NULL. */

fd_zstd_dstream_t *
fd_zstd_dstream_new( void * mem,
                     ulong  max_window_sz );

/* fd_zstd_dstream_delete destroys the dstream object and releases its
   memory region back to the caller.  Returns pointer to memory region
   on success (same as provided in call to new).  Acts as a no-op if
   dstream==NULL. */

void *
fd_zstd_dstream_delete( fd_zstd_dstream_t * dstream );

/* fd_zstd_dstream_reset resets the state of a dstream object, such that
   it expects the start of a frame. */

void
fd_zstd_dstream_reset( fd_zstd_dstream_t * dstream );

/* fd_zstd_dstream_read decompresses a fragment of stream data.

   *in_p is assumed to point to the next byte of compressed data.
   in_end points to one byte past the compressed data fragment.  *out_p
   is assumed to point to the next free byte in the destination buffer.
   out_end points to one byte past the destination buffer.

   On return, newly compressed data is written to the destination buffer
   and *out_p is updated to point to the next free byte, and *in_p is
   updated to point to the next byte not yet decompressed.
   If *out_p==out_end, the destination buffer was entirely filled.  The
   caller should retry with a new buffer in case not everything was
   flushed.  If *in_p==in_end, the compressed data fragment was fully
   consumed, and the caller should move on to the next fragment.

   Returns fd_io compatible error code.  Returns 0 if decompressor has
   made progress and is expecting more data.  Returns -1 (eof) if the
   current frame was fully decompressed, in which the caller may move on
   to the next frame (reset not required).  Note that -1 may be returned
   even if *in_p<in_end because the fragment could span multiple frames.
   Returns EPROTO on error.  The caller should reset the dstream in
   this case.  If opt_errcode!=NULL and an error occured, *opt_errcode
   is set accordingly. */

int
fd_zstd_dstream_read( fd_zstd_dstream_t *     dstream,
                      uchar const ** restrict in_p,
                      uchar const *           in_end,
                      uchar ** restrict       out_p,
                      uchar *                 out_end,
                      ulong *                 opt_errcode );

FD_PROTOTYPES_END

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_ballet_zstd_fd_zstd_h */
