#ifndef HEADER_fd_src_discof_backtest_fd_libc_zstd_h
#define HEADER_fd_src_discof_backtest_fd_libc_zstd_h

/* fd_libc_zstd.h provides APIs for retro-fitting libc FILE-based apps
   with Zstandard compression support. */

#if FD_HAS_ZSTD

#include "../../util/fd_util_base.h"
#include <stdio.h>
#include <zstd.h>

/* fd_zstd_rstream_open returns a decompressing libc FILE handle.  The
   returned file supports fread(), fclose(), ftell(), and fseek() to
   start-of-file.  Reading lazily decompresses input bytes from the
   underlying file.

   The ownership of file is moved (closing the returned FILE handle also
   closes the provided underlying file handle).  The dstream is only
   borrowed (closing the returned FILE handle leaves the dstream
   intact).

   Calls malloc().  Logs to FD_LOG_WARNING on decompression and I/O
   error. */

FILE *
fd_zstd_rstream_open( FILE *         file,
                      ZSTD_DStream * dstream,
                      ulong          buf_sz );

/* fd_zstd_wstream_open returns a compressing libc FILE handle.  The
   returned file supports append-only fwrite(), fclose(), and ftell().
   Writing to the returned FILE lazily compresses output bytes.
   fflush() does NOT behave correctly.

   The ownership of file is moved (closing the returned FILE handle also
   closes the provided underlying file handle).

   Calls malloc().  Logs to FD_LOG_WARNING on I/O error. */

FILE *
fd_zstd_wstream_open( FILE * file,
                      int    level,
                      ulong  buf_sz );

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_discof_backtest_fd_libc_zstd_h */
