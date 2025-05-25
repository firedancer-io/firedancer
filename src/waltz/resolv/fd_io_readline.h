#ifndef HEADER_fd_src_waltz_resolv_fd_io_readline_h
#define HEADER_fd_src_waltz_resolv_fd_io_readline_h

/* fd_io_readline.h is a helper for doing buffered line reads. */

#include "../../util/io/fd_io.h"

FD_PROTOTYPES_BEGIN

/* fd_io_fgets consumes bytes from istream into the array pointed to by
   str until str_max-1 bytes are read, a newline is encountered, or the
   end of the underlying file is reached.  Returns NULL if an error
   occurred (sets *err to positive errno) or EOF is reached before
   reading any bytes (set *err to -1).  Otherwise, returns the null-
   terminated string at str (which may contain a newline char), and sets
   *err to 0 (if newline was found) or -1 (if EOF was found).  Assumes
   that istream buffer size is at least str_max and non-blocking.
   Newline is '\n'. */

char *
fd_io_fgets( char * restrict            str,
             int                        str_max,
             fd_io_buffered_istream_t * istream,
             int *                      err );

int
fd_io_fgetc( fd_io_buffered_istream_t * istream,
             int *                      err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_resolv_fd_io_readline_h */
