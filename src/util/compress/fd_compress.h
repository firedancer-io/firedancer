#ifndef HEADER_fd_src_util_compress_fd_compress_h
#define HEADER_fd_src_util_compress_fd_compress_h

#include "../fd_util_base.h"

/* fd_decompress_cb_t is called by the decompressor with pieces of
   decompressed data.  arg is the context pointer.  data points to the
   first byte of decompressed data chunk.  sz is the number of bytes.
   lifetime of data is until this callback returns.  Returns zero if
   decompressor should continue.  Returns non-zero if decompressor
   should gracefully exit with success. */

typedef int
(* fd_decompress_cb_t)( void *        arg,
                        uchar const * data,
                        ulong         sz );

FD_PROTOTYPES_BEGIN

/* fd_decompress_bz2 decompresses a BZip2 compressed file.  fd is a file
   descriptor positioned at the beginning of the BZ2 stream (may be non-
   blocking).  cb is the callback function that is invoked for each
   piece of decompressed data.  Pieces are handled in order such that
   concatenating them yields the original data.  arg is the context
   pointer passed to each cb invocation.  Returns 0 when end of bzip2
   stream has been reached without error or cb returned non-zero.  On
   failure, returns errno indicating reason for failure.  Reasons for
   failure include I/O error, corrupt data, or unexpected EOF.  Prints
   failure reason to warn log.  Calls fd_io_read to perform reads.  Does
   not close fd. Aborts program on fatal error (such as failed to init
   BZip stream) Requires at least 1 MiB free stack space.

   fd_decompress_zstd is like fd_decompress_bz2, but for Zstandard
   compressed streams.  Unlike the bz2 variant will attempt to
   decompress all the way to end-of-file, as zstd has no "end of stream"
   indicator (only "end of frame", but there can be multiple frames in a
   stream). */

#if FD_HAS_BZ2

int
fd_decompress_bz2( int                fd,
                   fd_decompress_cb_t cb,
                   void *             arg );

#endif /* FD_HAS_BZ2 */

#if FD_HAS_ZSTD

int
fd_decompress_zstd( int                fd,
                    fd_decompress_cb_t cb,
                    void *             arg );

#endif /* FD_HAS_ZSTD */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_compress_fd_compress_h */
