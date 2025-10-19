#ifndef HEADER_fd_src_ballet_sha1_fd_sha1_h
#define HEADER_fd_src_ballet_sha1_fd_sha1_h

#include "../fd_ballet_base.h"

/* fd_sha1_hash computes the SHA1 hash of the input data provided and
   writes the result into the hash buffer.  The output buffer must be at
   least 20 bytes.  Returns the output buffer. */

uchar *
fd_sha1_hash( uchar const * data,
              ulong         data_len,
              uchar *       hash );

#endif /* HEADER_fd_src_ballet_sha1_fd_sha1_h */
