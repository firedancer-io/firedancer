#ifndef HEADER_fd_src_util_compress_fd_compress_h
#define HEADER_fd_src_util_compress_fd_compress_h

/* fd_compress provides utilities for Zstandard compression. */

#if FD_HAS_ZSTD

#include "../fd_util_base.h"

/* Compress API *******************************************************/

/* fd_zstd_ofstream_t is used to compress a stream of bytes and write
   it to a file.  Uses libzstd's experimental memory management API to
   support operation without dynamic allocation.  Synchronously writes
   the in-memory buffer out to a file descriptor while compressing
   (which is slow).  Not position independent and thus cannot be shared
   across different address spaces. */

struct __attribute__((aligned(32UL))) fd_zstd_ofstream {
  ulong   magic;     /* ==FD_ZSTD_OFSTREAM_MAGIC */

  void *  ctx;       /* pointer to ZSTD_CStream */
  uchar * buf;       /* points to in-memory compressed buffer */
  ulong   buf_sz;    /* number of bytes currently in buffer */
  ulong   buf_cap;   /* size of buffer */
  int     file;      /* file descriptor */

  ulong   raw_sz;    /* bytes dispatched via API so far (uncompressed) */
  ulong   comp_sz;   /* bytes written to file so far (compressed)   */
};

typedef struct fd_zstd_ofstream fd_zstd_ofstream_t;

/* FD_ZSTD_OFSTREAM_MAGIC identifies an fd_zstd_ofstream_t at runtime.
   This magic number is Firedancer-internal and not used by the zstd
   file format. */

#define FD_ZSTD_OFSTREAM_MAGIC (0x91fa84d67a86c591UL)

/* fd_zstd_compress_{align,footprint} return parameters for the memory
   region backing a fd_zstd_compress_t object.  align returns the byte
   alignment of the memory region.  footprint returns the minimum byte
   size of the region.

   - lvl controls the Zstandard compression level (in [1,22]).
   - bufsz is the size of the in-memory buffer.  Can be set to 0UL if
     user wishes to use an externally provided buffer instead. */

FD_FN_CONST ulong
fd_zstd_ofstream_align( void );

ulong
fd_zstd_ofstream_footprint( int   lvl,
                            ulong bufsz );

FD_PROTOTYPES_BEGIN

/* fd_zstd_ofstream_new creates a new Zstandard stream compression
   context.  mem points to the memory region that will hold the context
   object.  mem adheres to above parameters.  lvl and bufsz must be
   equal to the param passed to fd_zstd_compress_footprint used when
   creating the mem region.  file is a writable file descriptor.
   Returns a qualified handle to the compression context (should not be
   assumed to be a simple cast) on success. Handle may not be shared
   across threads.  On failure, returns NULL and logs reason to warning
   log.  Reasons include invalid memory region, invalid compression
   level, or internal libzstd error. */

void *
fd_zstd_ofstream_new( void * mem,
                      int    lvl,
                      ulong  bufsz,
                      int    file );

/* fd_zstd_ofstream_join joins the caller to the given
   fd_zstd_ofstream_t. */

fd_zstd_ofstream_t *
fd_zstd_ofstream_join( void * shcomp );

/* fd_zstd_ofstream_leave terminates a local join to a
   fd_zstd_ofstream_t.*/

void *
fd_zstd_ofstream_leave( fd_zstd_ofstream_t * comp );

/* fd_zstd_compress_delete releases a Zstandard compression context.
   Releases and returns the memory region provided to
   fd_zstd_compress_new. */

void *
fd_zstd_ofstream_delete( fd_zstd_ofstream_t * comp );

/* fd_zstd_ofstream_compress compresses a chunk of bytes into the in-
   memory buffer.  If buffer is full, also flushes buffer out to file.
   comp is the output stream.  data points to the first byte of the
   uncompressed data.  data_sz is the number of bytes, where
   data_sz<=max_data_sz associated with the context.  Returns 0 on
   success.  On failure, returns errno compatible reason and writes to
   log.  Reasons for failure include I/O error or internal error in
   libzstd. */

int
fd_zstd_ofstream_compress( fd_zstd_ofstream_t * comp,
                           void const *         data,
                           ulong                data_sz );

/* fd_zstd_ofstream_flush writes all in-memory buffer state out to file.
   Return value documented above. */

int
fd_zstd_ofstream_flush( fd_zstd_ofstream_t * comp );

/* fd_zstd_ofstream_end finishes the compression frame and flushes to
   disk.  This must be called at EOF.  Return value documented above.
   Calling fd_zstd_ofstream_compress after flush creates a new
   compression frame. */

int
fd_zstd_ofstream_end( fd_zstd_ofstream_t * comp );

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_util_compress_fd_compress_h */
