#include "fd_ar.h"

#if FD_HAS_HOSTED

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* An fd_ar_hdr_t is the raw header of a file entry in the ar file.  It
   is not clear how strict ar is about ASCII encoding in these fields
   (is leading whitespace okay, is trailing whitespace okay, is garbage
   allowed in trailing field, are explicit + allowed, are signed
   quantities allowed, etc).  We currently handle the encoding:

   field -> ^ [zero or more chars of whitespace]
      width | [optional '+' or '-']
      chars | [one or more chars of radix digits]
            v [zero or more non-radix-digit chars (including '\0')]

   (That is, stuff strtol can convert and error trap.)

   Leading zeros are allowed as 'radix digits' and do not trigger radix
   detection; the spec dictates whether a string is interpreted as decimal or
   octal.

   We convert fields to a long.  Though the fields here clearly can be
   stored more compactly, overflow / underflow is not possible into a
   long and it is also readily apparent that the ar format cannot handle
   routine things like very large files.  It is conceivable in the
   future we might want to add support for variations on this file
   format and would like to avoid requiring user facing changes to use a
   different API.

   We also debatably allow negative values for all fields but filesz and
   kick the interpretation of that to the user (we might change this
   behavior in the future to give stricter guarantees).  The filesz
   field val is required to be non-negative but we still store it in a
   long type for fseek friendliness (fseek with negative values for
   filesz could generate unexpected results, including infinite loop ar
   file iterations by using a filesz = -hdr_sz). */

#define FD_AR_HDR_IDENT_SZ  (FD_AR_META_IDENT_SZ-1UL)
#define FD_AR_HDR_MTIME_SZ  (12UL)
#define FD_AR_HDR_UID_SZ    ( 6UL)
#define FD_AR_HDR_GID_SZ    ( 6UL)
#define FD_AR_HDR_MODE_SZ   ( 8UL)
#define FD_AR_HDR_FILESZ_SZ (10UL)
#define FD_AR_HDR_MAGIC     ((ushort)0x0a60)

struct fd_ar_hdr {
  char   ident     [ FD_AR_HDR_IDENT_SZ  ]; /* File identifier,                             WARNING: may not be '\0' terminated */
  char   mtime_dec [ FD_AR_HDR_MTIME_SZ  ]; /* File modification timestamp (ASCII decimal), WARNING! may not be '\0' terminated */
  char   uid_dec   [ FD_AR_HDR_UID_SZ    ]; /* Owner ID (ASCII decimal),                    WARNING: may not be '\0' terminated */
  char   gid_dec   [ FD_AR_HDR_GID_SZ    ]; /* Group ID (ASCII decimal),                    WARNING: may not be '\0' terminated */
  char   mode_oct  [ FD_AR_HDR_MODE_SZ   ]; /* File mode (ASCII octal),                     WARNING: may not be '\0' terminated */
  char   filesz_dec[ FD_AR_HDR_FILESZ_SZ ]; /* File size (ASCII decimal),                   WARNING: may not be '\0' terminated */
  ushort magic;                             /* ==FD_AR_HDR_MAGIC */
};

typedef struct fd_ar_hdr fd_ar_hdr_t;

static int
fd_ar_ascii_to_long( char const * field,
                     ulong        width,   /* Should be less than 32 */
                     int          base,    /* Should be a supported strtol base */
                     long *       _val ) {

  /* Turn field into a proper cstr */

  if( FD_UNLIKELY( width>=32UL ) ) return EINVAL;
  char cstr[ 32UL ];
  memcpy( cstr, field, width );
  cstr[ width ] = '\0';

  /* Do the conversion.  Note: strtol will set errno to EINVAL is an
     unsupported base (and maybe whitespace/empty string depending on
     implementation) and ERANGE if overflow / underflow.  FIXME: This is
     probably simple enough to ween off stdlib (it'd probably be
     cleaner, faster and have less strtol weirdness to deal with). */

  char * endptr;
  errno = 0;
  long val = strtol( cstr, &endptr, base );
  if( FD_UNLIKELY( errno        ) ) return errno;
  if( FD_UNLIKELY( cstr==endptr ) ) return EINVAL; /* Consistent handling of whitespace / empty string */

  *_val = val;
  return 0;
}

int
fd_ar_read_init( void * _stream ) {
  FILE * stream = (FILE *)_stream;

  /* Check input args */

  if( FD_UNLIKELY( !stream ) ) return EINVAL;

  /* Check archive header magic */

  char magic[ 8 ];
  if( FD_UNLIKELY( fread( magic, 8UL, 1UL, stream )!=1UL ) ) return FD_LIKELY( feof( stream ) ) ? ENOENT : EIO;
  if( FD_UNLIKELY( memcmp( magic, "!<arch>\n", 8UL )     ) ) return EPROTO; /* Could do this single asm with ulong compare */

  /* Everything ok */

  return 0;
}

int
fd_ar_read_next( void *         _stream,
                 fd_ar_meta_t * opt_meta ) {
  FILE * stream = (FILE *)_stream;

  /* Check input args */

  if( FD_UNLIKELY( !stream ) ) return EINVAL;

  /* Read file header.  Note: Headers are two-byte aligned */

  long pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) ) return EIO;
  if( (pos&1L) && FD_UNLIKELY( fseek( stream, 1L, SEEK_CUR )<0L ) ) return FD_LIKELY( feof( stream ) ) ? ENOENT : EIO;

  fd_ar_hdr_t hdr[1];
  if( FD_UNLIKELY( fread( hdr, sizeof(fd_ar_hdr_t), 1UL, stream )!=1UL ) ) return FD_LIKELY( feof( stream ) ) ? ENOENT : EIO;
  if( FD_UNLIKELY( hdr->magic!=FD_AR_HDR_MAGIC                         ) ) return EPROTO;

  /* Parse the file header */

  fd_ar_meta_t meta[1];
  if( FD_UNLIKELY( fd_ar_ascii_to_long( hdr->mtime_dec,  FD_AR_HDR_MTIME_SZ,  10, &meta->mtime  ) ) ) return EPROTO;
  if( FD_UNLIKELY( fd_ar_ascii_to_long( hdr->uid_dec,    FD_AR_HDR_UID_SZ,    10, &meta->uid    ) ) ) return EPROTO;
  if( FD_UNLIKELY( fd_ar_ascii_to_long( hdr->gid_dec,    FD_AR_HDR_GID_SZ,    10, &meta->gid    ) ) ) return EPROTO;
  if( FD_UNLIKELY( fd_ar_ascii_to_long( hdr->mode_oct,   FD_AR_HDR_MODE_SZ,    8, &meta->mode   ) ) ) return EPROTO;
  if( FD_UNLIKELY( fd_ar_ascii_to_long( hdr->filesz_dec, FD_AR_HDR_FILESZ_SZ, 10, &meta->filesz ) ) ) return EPROTO;
  if( FD_UNLIKELY( meta->filesz<0L ) ) return EPROTO;
  memcpy( meta->ident, hdr->ident, FD_AR_HDR_IDENT_SZ );
  meta->ident[ FD_AR_HDR_IDENT_SZ ] = '\0';

  /* Everything ok */

  if( opt_meta ) *opt_meta = *meta;
  return 0;
}

#else /* Not supported on this target */

int fd_ar_read_init( void * stream                      ) { (void)stream;             FD_COMPILER_MFENCE(); return 1; }
int fd_ar_read_next( void * stream, fd_ar_meta_t * meta ) { (void)stream; (void)meta; FD_COMPILER_MFENCE(); return 1; }

#endif
