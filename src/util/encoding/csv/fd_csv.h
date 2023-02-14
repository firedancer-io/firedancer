#ifndef HEADER_fd_src_util_cstr_fd_csv_h
#define HEADER_fd_src_util_cstr_fd_csv_h

/* APIs for handling CSV (comma separated value) files.

   This implementation is compliant to RFC 4180.
   https://datatracker.ietf.org/doc/rfc4180/ */

#include "../../fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_csv_read_record: Parses a CSV record from the given stream.

   A record is usually a single line of CSV containing multiple fields,
   though quotes allow splitting a record over multiple lines.

     header1,header2,header3
     foo,bar,bla
     ,,
     hello,"world",
     ...

   On entry, assumes stream is positioned at or before the start of a
   record. If FD_HAS_HOSTED, stream should point to an open FILE handle.
   Otherwise stream should be to the equivalent is provided for that
   target.

   Returns 0 on success and a non-zero strerror compatible error code on
   failure.  If successful or EPROTO, the stream will be positioned
   after the end of the line that includes the record.  Writes pointers
   to the field cstrs into the `col_cstrs` array with `col_cnt` element
   count.  The content of `col_cstrs` is valid until the next call to
   `fd_csv_read_record`.

   On error, the contents of the `col_strs` array are undefined. On any
   error other than `EPROTO`, the stream position is undefined.

   Error codes include:
   - EINVAL: NULL col_cstrs, zero col_cnt, nul sep, nul quote,
             ambiguous sep/quote, whitespace sep/quote, NULL stream
   - ENOENT: end of stream reached
   - EIO:    failed due to stream i/o failure
   - EPROTO: failed due to parsing error

   Reasons for parsing errors include:
   - the number of columns found does not match `col_cnt`
   - unterminated quote
   - record size exceeds internal buffer size
   Additional information provided by `fd_csv_strerror`.

   ### Security

   Implements parsing in O(n) complexity and is designed to be safe
   to call on streams containing untrusted input.  However, this API is
   primarily intended for testing and offers no promise of determinism.

   ### Caveats

   TODO Current implementation uses double buffering (FILE buf and
        custom TLS buf).  The FILE buf is used to reduce the amount
        of read syscalls. This same buffer cannot be used as backing
        storage for cstrs returned back to the user, requiring a second
        copy.
        Possible performance improvement by switching to unbuffered file
        I/O and a custom ring buffer instead. */
int
fd_csv_read_record( char ** col_cstrs,
                    ulong   col_cnt,
                    int     sep,
                    int     quote,
                    void *  stream );

/* fd_csv_strerror: Returns a cstr describing the source line and error
   kind after the last call to `fd_csv_read_record` from the same thread
   returned non-zero.

   Always returns a valid cstr, though the content is undefined in case
   the last call to `fd_csv_read_record` returned zero (success) or
   `fd_csv_read_record` was never called from the current thread. */
char const *
fd_csv_strerror( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_cstr_fd_csv_h */
