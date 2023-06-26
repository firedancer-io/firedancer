#ifndef HEADER_fd_src_archive_fd_ar_h
#define HEADER_fd_src_archive_fd_ar_h

/* AR(5) is a simple archive format combining multiple files into one.
   The file format is structurally similar to TAR.

   This package provides a simple streaming AR reader.

   ### File Format

   Reference: https://www.freebsd.org/cgi/man.cgi?query=ar&sektion=5

      +------------------------+
      | Archive Magic          | 8 bytes "<arch>!\n"
      +------------------------+
      | File Header 0          | 60 bytes
      +------------------------+
      | File Content           | variable length
      |                        |
      +------------------------+
      | File Header 1          | 60 bytes (aligned to 2 bytes)
      +------------------------+
      | File Content           | variable length
      |                        |
      ..........................

   ### Usage

   The `ar(1)` tool from GNU binutils can be used to create such archive files.

      ar rcDS <archive_file> <file> <file> <file...>

   Basic usage:

     ... at this point, stream should be pointed at the first byte
     ... of the ar file magic

     fd_ar_read_init( stream );
     for(;;) {
       fd_ar_meta_t meta[1];
       if( fd_ar_read_next( stream, meta ) ) break;

       ... at this point, stream is pointed at first byte of contents of
       ... the next unprocessed file in the ar and there are
       ... meta->filesz bytes ni this file
       ... process next file here, advancing the stream position exactly

       ... meta->filesz bytes before next iteration
     }

   More nuanced error handling and what not is possible.  See
   descriptions below. */

#include "../fd_util_base.h"

/* See note in fd_ar.c for details on use of long for these fields. */

#define FD_AR_META_IDENT_SZ (17UL) /* 16 + 1 for '\0' termination */

struct fd_ar_meta {
  long mtime;
  long uid;
  long gid;
  long mode;
  long filesz;                       /* Guaranteed to be non-negative */
  char ident[ FD_AR_META_IDENT_SZ ]; /* Guaranteed '\0' terminated */
};

typedef struct fd_ar_meta fd_ar_meta_t;

FD_PROTOTYPES_BEGIN

/* fd_ar_read_init starts reading an ar archive in the given stream.  On
   entry, assumes stream is positioned on the first byte of the ar
   magic.  If FD_HAS_HOSTED, stream is FILE * pointer.  Otherwise stream
   should be the equivalent for that target.

   Returns 0 on success and non-zero strerror compatible error code on
   failure.  If successful, the stream will be positioned on the first
   byte immediately after the ar magic.  If not, the stream state is
   undefined.

   Error codes include:

   - EINVAL: NULL stream
   - ENOENT: failed due to EOF
   - EIO:    failed due to stream i/o failure
   - EPROTO: failed due to malformed ar file (bad magic) */

int
fd_ar_read_init( void * stream );

/* fd_ar_read_next starts reading the archive file in the given stream.
   On entry, assumes stream is positioned on the first byte immediately
   after the archive magic or the first byte immediately after the just
   processed archive file content.  If FD_HAS_HOSTED, stream should
   point to an open FILE handle.  Otherwise stream should be to the
   equivalent is provided for that target.

   Returns 0 on success and non-zero strerror compatible error code on
   failure.  If successful, the stream will be positioned on the first
   byte of the file content to process next and meta will be populated
   with details from the archive header.

   If opt_meta is non-NULL, on success, *opt_meta will be populated with
   archive file metadata on return.  Of note, the size of the file
   contents is opt_meta->filesz bytes (a non-negative number).
   Otherwise, *opt_meta will be untouched.

   Before fd_ar_read_next is called on the get the next file, it should
   position stream just after the last byte of the file contents.  E.g.
   to skip over file contents in a hosted environment, provide opt_meta
   and do:

     fseek( stream, opt_meta->filesz, SEEK_CUR )

   If the caller did not provide opt_meta to get the filesz, the caller
   should know via other means how to position the stream after the file
   contents.

   Error codes include:

   - EINVAL: NULL stream
   - ENOENT: failed due to EOF
   - EIO:    failed due to stream i/o failure
   - EPROTO: failed due to malformed ar file (bad magic) */

int
fd_ar_read_next( void *         stream,
                 fd_ar_meta_t * opt_meta );

/* FIXME: CONSIDER AN FD_AR_READ_FINI THAT WOULD MOVE THE STREAM POINTER
   TO THE END OF THE AR FILE? */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_archive_fd_ar_h */
