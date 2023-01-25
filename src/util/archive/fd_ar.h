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

      ar rcDS <archive_file> <file> <file> <file...> */

#include <stdio.h>
#include <stdlib.h>

#include "../fd_util_base.h"

#define FD_AR_IDENT_SZ  16
#define FD_AR_MTIME_SZ  12
#define FD_AR_UID_SZ     6
#define FD_AR_GID_SZ     6
#define FD_AR_MODE_SZ    8
#define FD_AR_FILESZ_SZ 10

#define FD_AR_FILE_MAGIC ((ushort)0x0a60)

/* fd_ar is the header of each file entry in the ar file. */

struct __attribute__((packed,aligned(2))) fd_ar {
  /* File identifier */
  char ident[ FD_AR_IDENT_SZ ];

  /* File modification timestamp (ASCII decimal) */
  char mtime_dec[ FD_AR_MTIME_SZ ];

  /* Owner ID (ASCII decimal) */
  char uid_dec[ FD_AR_UID_SZ ];

  /* Group ID (ASCII decimal) */
  char gid_dec[ FD_AR_GID_SZ ];

  /* File mode (ASCII octal) */
  char mode_oct[ FD_AR_MODE_SZ ];

  /* File size (ASCII decimal) */
  char filesz_dec[ FD_AR_FILESZ_SZ ];

  /* File header magic (0x0a60) */
  ushort magic;
};
typedef struct fd_ar fd_ar_t;

FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, ident      )== 0UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, mtime_dec  )==16UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, uid_dec    )==28UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, gid_dec    )==34UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, mode_oct   )==40UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, filesz_dec )==48UL, alignment );
FD_STATIC_ASSERT( __builtin_offsetof( fd_ar_t, magic      )==58UL, alignment );

FD_STATIC_ASSERT( sizeof(fd_ar_t)==60, alignment );

/* fd_ar_filesz returns the length of the data stream that follows
   the given archive file header.

   Returns a negative number on error.. */
FD_FN_PURE static inline long
fd_ar_filesz( fd_ar_t const * ar ) {
  char * endptr;
  long n = strtol( ar->filesz_dec, &endptr, 10 );
  if( FD_UNLIKELY( ar->filesz_dec == endptr ) ) return -1;
  return n;
}

/* fd_ar_open attaches to the given stream for reading.

   Sets `errno` on failure. Special `errno` values:
     `EPROTO`: stream is not an AR file */
int
fd_ar_open( FILE * stream );

/* fd_ar_next reads the next archive file header from the stream.

   Sets `errno` on failure. Special `errno` values:
     `ENOENT`: end of archive reached
     `EPROTO`: malformed AR entry */
int
fd_ar_next( FILE *    stream,
            fd_ar_t * hdr );

#endif /* HEADER_fd_src_archive_fd_ar_h */
