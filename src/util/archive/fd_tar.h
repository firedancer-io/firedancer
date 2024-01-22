#ifndef HEADER_fd_src_archive_fd_tar_h
#define HEADER_fd_src_archive_fd_tar_h

/* fd_tar implements the ustar and old-GNU versions of the TAR file
   format.  This is not a general-purpose TAR implementation.  It is
   currently only intended for loading Solana snapshots. */

#include "../fd_util_base.h"

/* File Format ********************************************************/

/* fd_tar_meta_t is the ustar/OLDGNU version of the TAR header. */

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

FD_FN_PURE ulong
fd_tar_meta_get_size( fd_tar_meta_t const * meta );

/* fd_tar_set_octal is a helper function to write 12-byte octal fields */

int
fd_tar_set_octal( char  buf[ static 12 ],
                  ulong val );

/* fd_tar_meta_set_size sets the size field.  Returns 1 on success, 0
   if sz is too large to be represented in TAR header. */

static inline int
fd_tar_meta_set_size( fd_tar_meta_t * meta,
                      ulong           sz ) {
  return fd_tar_set_octal( meta->size, sz );
}

/* fd_tar_meta_set_mtime sets the modification time field.  Returns 1
   on success, 0 if time cannot be represented in TAR header. */

static inline int
fd_tar_meta_set_mtime( fd_tar_meta_t * meta,
                       ulong           mtime ) {
  return fd_tar_set_octal( meta->mtime, mtime );
}

FD_PROTOTYPES_END

/* Streaming reader ***************************************************/

typedef struct fd_tar_reader fd_tar_reader_t;

/* fd_tar_file_fn_t is called by fd_tar when a new file was encountered.
   cb_arg is the callback context value. meta is the file header
   (lifetime until return).  sz is the expected file size that follows
   (via read callbacks).  The actual read size might differ in case of
   errors (e.g. unexpected EOF).  Returns 0 on success and non-zero if
   tar reader should stop. */

typedef int
(* fd_tar_file_fn_t)( void *                cb_arg,
                      fd_tar_meta_t const * meta,
                      ulong                 sz );

/* fd_tar_read_cb_t is called by fd_tar when a new chunk of data has
   been read.  Each read callback is associated with the last file
   callback.  Read callbacks are issued in order such that concatenating
   all buffers results in the correct file content.  Returns 0 on
   success and non-zero if tar reader should stop.

   cb_arg is the callback context value.  buf points to the first byte
   of the chunk.  bufsz is the byte count.  The lifetime of buf is until
   the callback returns. */

typedef int
(* fd_tar_read_fn_t)( void *       cb_arg,
                      void const * buf,
                      ulong        bufsz );

/* fd_tar_read_vtable_t is the virtual function table of the
   fd_tar_reader_t consumer object. */

struct fd_tar_read_vtable {
  fd_tar_file_fn_t file;
  fd_tar_read_fn_t read;
};

typedef struct fd_tar_read_vtable fd_tar_read_vtable_t;

/* fd_tar_reader_t is a streaming TAR reader using a callback API for
   delivering data.  To use, feed it the chunks of the TAR stream via
   fd_tar_read.  There is no restriction on the size and alignment of
   these chunks, other than that the chunks are supplied in order and
   gapless.  The resulting callback sequence is (1x file, Nx read, 1x
   file, Nx read ...).  As in: Each new file encountered creates a file
   callback and a variable number of read callbacks. */

struct fd_tar_reader {

  /* Buffered file header.  Required because a file header might be
     split across multiple fd_tar_read calls. */
  union {
    uchar         buf[ sizeof(fd_tar_meta_t) ];
    fd_tar_meta_t header;
  };

  ulong pos;      /* Number of bytes consumed */
  ulong buf_ctr;  /* Write cursor in file header */
  ulong file_sz;  /* Number of file bytes left */

  /* Callback parameters */
  fd_tar_read_vtable_t cb_vt;
  void *               cb_arg;

};

FD_PROTOTYPES_BEGIN

/* fd_tar_reader_{align,footprint} return parameters for the memory
   region backing a fd_tar_reader_t. */

FD_FN_CONST static inline ulong
fd_tar_reader_align( void ) {
  return alignof(fd_tar_reader_t);
}

FD_FN_CONST static inline ulong
fd_tar_reader_footprint( void ) {
  return sizeof(fd_tar_reader_t);
}

/* fd_tar_reader_new creates a new TAR reader.  mem is the memory region
   that will hold the fd_tar_reader_t (matches above align/ footprint
   requirements).  cb_vt contains the callback function pointers of
   the recipient.  cb_vt pointer is borrowed until this function
   returns.  cb_arg is the callback context value (usually a pointer to
   the recipient object).  Returns a qualified handle to the reader
   object in mem on success.  On failure, returns NULL and writes reason
   to warning log.  Reasons for failure include invalid memory region or
   NULL callback. */

fd_tar_reader_t *
fd_tar_reader_new( void *                       mem,
                   fd_tar_read_vtable_t const * cb_vt,
                   void *                       cb_arg );

/* fd_tar_reader_delete destroys a .tar reader and frees any allocated
   resources.  Returns the underlying memory region back to the caller. */

void *
fd_tar_reader_delete( fd_tar_reader_t * reader );

/* fd_tar_read processes a chunk of the TAR stream.  Issues callbacks
   when file headers or content are read.  reader is an fd_tar_reader_t
   pointer.  data points to the first byte of the data chunk.  data_sz
   is the byte count.  data_sz==0UL is a no-op.  Returns 0 on success.
   Returns -1 on end-of-file.  On failure, returns positive errno
   compatible error code.  In case of error, caller should delete reader
   and must not issue any more fd_tar_read calls.  Suitable as a
   fd_decompress_cb_t callback. */

int
fd_tar_read( fd_tar_reader_t * reader,
             uchar const *     data,
             ulong             data_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_archive_fd_tar_h */
