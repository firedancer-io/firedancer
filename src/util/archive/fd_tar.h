#ifndef HEADER_fd_src_util_archive_fd_tar_h
#define HEADER_fd_src_util_archive_fd_tar_h

/* fd_tar implements the ustar and old-GNU versions of the TAR file
   format. This is not a general-purpose TAR implementation.  It is
   currently only intended for loading and writing Solana snapshots. */

#include "../bits/fd_bits.h"

/* File Format ********************************************************/

/* The high level format of a tar archive/ball is a set of 512 byte blocks.
   Each file will be described a tar header (fd_tar_meta_t) and will be
   followed by the raw bytes of the file. The last block that is used for
   the file will be padded to fit into a tar block. When the archive is
   completed, it will be trailed by two EOF blocks which are populated with
   zero bytes. */

/* fd_tar_meta_t is the ustar/OLDGNU version of the TAR header. */

#define FD_TAR_BLOCK_SZ (512UL)

struct __attribute__((packed)) fd_tar_meta {
# define FD_TAR_NAME_SZ (100)
  /* 0x000 */ char name    [ FD_TAR_NAME_SZ ];
  /* 0x064 */ char mode    [   8 ];
  /* 0x06c */ char uid     [   8 ];
  /* 0x074 */ char gid     [   8 ];
  /* 0x07c */ char size    [  12 ];
  /* 0x088 */ char mtime   [  12 ];
  /* 0x094 */ char chksum  [   8 ];
  /* 0x09c */ char typeflag;
  /* 0x09d */ char linkname[ 100 ];
  /* 0x101 */ char magic   [   6 ];
  /* 0x107 */ char version [   2 ];
  /* 0x109 */ char uname   [  32 ];
  /* 0x129 */ char gname   [  32 ];
  /* 0x149 */ char devmajor[   8 ];
  /* 0x151 */ char devminor[   8 ];
  /* 0x159 */ char prefix  [ 155 ];
  /* 0x1f4 */ char padding [  12 ];
};

typedef struct fd_tar_meta fd_tar_meta_t;

/* FD_TAR_MAGIC is the only value of fd_tar_meta::magic supported by
   fd_tar. */

#define FD_TAR_MAGIC "ustar"

/* Known file types */

#define FD_TAR_TYPE_NULL      ('\0')  /* implies FD_TAR_TYPE_REGULAR */
#define FD_TAR_TYPE_REGULAR   ('0')
#define FD_TAR_TYPE_HARD_LINK ('1')
#define FD_TAR_TYPE_SYM_LINK  ('2')
#define FD_TAR_TYPE_CHAR_DEV  ('3')
#define FD_TAR_TYPE_BLOCK_DEV ('4')
#define FD_TAR_TYPE_DIR       ('5')
#define FD_TAR_TYPE_FIFO      ('6')

FD_PROTOTYPES_BEGIN

/* fd_tar_meta_is_reg returns 1 if the file type is 'regular', and 0
   otherwise. */

FD_FN_PURE static inline int
fd_tar_meta_is_reg( fd_tar_meta_t const * meta ) {
  return ( meta->typeflag == FD_TAR_TYPE_NULL    )
       | ( meta->typeflag == FD_TAR_TYPE_REGULAR );
}

/* fd_tar_meta_get_size parses the size field of the TAR header.
   Returns ULONG_MAX if parsing failed. */

FD_FN_PURE FD_FN_UNUSED static ulong
fd_tar_meta_get_size( fd_tar_meta_t const * meta ) {
  char const * buf = meta->size;
  if( ((uchar)buf[0]) & 0x80U ) {
    /* OLDGNU tar files may use a binary size encoding */
    return fd_ulong_bswap( FD_LOAD( ulong, buf+4 ) );
  }

  ulong ret = 0UL;
  for( char const * p=buf; p<buf+12; p++ ) {
    if( *p == '\0' ) break;
    ret = (ret << 3) + (ulong)(*p - '0');
  }

  return ret;
}

/* fd_tar_set_octal is a helper function to write 12-byte octal fields */

int
fd_tar_set_octal( char  buf[ static 12 ],
                  ulong val );

/* fd_tar_meta_set_size sets the size field.  Returns 1 on success, 0
   if sz is too large to be represented in TAR header. Set size using the
   OLDGNU size extension to allow for unlimited file sizes. The first byte
   must be 0x80 followed by 0s and then the size in binary. */

static inline int
fd_tar_meta_set_size( fd_tar_meta_t * meta,
                      ulong           sz ) {
  meta->size[ 0 ] = (char)0x80;
  FD_STORE( ulong, meta->size + 4UL, fd_ulong_bswap( sz ) );
  return 1;
}

/* fd_tar_meta_set_mtime sets the modification time field.  Returns 1
   on success, 0 if time cannot be represented in TAR header. */

static inline int
fd_tar_meta_set_mtime( fd_tar_meta_t * meta,
                       ulong           mtime ) {
  return fd_tar_set_octal( meta->mtime, mtime );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_archive_fd_tar_h */
