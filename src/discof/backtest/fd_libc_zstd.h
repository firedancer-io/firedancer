#ifndef HEADER_fd_src_discof_backtest_fd_libc_zstd_h
#define HEADER_fd_src_discof_backtest_fd_libc_zstd_h

#if FD_HAS_ZSTD

#include <stdio.h>
#include <zstd.h>

FILE *
fd_zstd_rstream_open( FILE *         file,
                      ZSTD_DStream * dstream );

FILE *
fd_zstd_wstream_open( FILE * file );

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_discof_backtest_fd_libc_zstd_h */
