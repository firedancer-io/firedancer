#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_reader_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_reader_h

#include "fd_solcap.pb.h"
#include "fd_solcap_proto.h"

#if FD_HAS_HOSTED

/* fd_solcap_chunk_iter_t helps with iterating through the chunks of a
   solcap file */

struct fd_solcap_chunk_iter {
  void *            stream;
  fd_solcap_chunk_t chunk;
  int               err;
  ulong             chunk_off;  /* Absolute file offset of current chunk */
  ulong             chunk_end;  /* Absolute file offset of next chunk    */
};
typedef struct fd_solcap_chunk_iter fd_solcap_chunk_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_solcap_chunk_iter_new initializes the given iter.  stream is a
   file handle (FILE * or platform equivalent).  The stream cursor must
   point to the first chunk (not the file header).  To read the first
   and subsequent chunks, use fd_solcap_chunk_iter_next.  It is U.B. to
   call any other reader methods than "next" after "new". */

fd_solcap_chunk_iter_t *
fd_solcap_chunk_iter_new( fd_solcap_chunk_iter_t * iter,
                          void *                   stream );

/* fd_solcap_chunk_iter_next reads the next chunk header.  Safe to call
   even if stream cursor was modified by user.  On success, returns the
   file offset pointing to the first byte of the chunk.  The cursor of
   iter->stream is undefined, so user should use fseek() with SEEK_SET
   to find data of interest.  Typically use as follows:

      long chunk_goff = fd_solcap_chunk_iter_next( iter );
      if( FD_UNLIKELY( chunk_goff<0L ) ) { ... }
      fseek( iter->stream, chunk_goff + my_offset, SEEK_SET );

   On failure, returns -1L.  Reasons for failure are end-of-file, I/O
   error, or parse error.  errno-like code can be read via
   fd_solcap_chunk_iter_err, which returns 0 on end-of-file.  Reasons
   for error (other than EOF) are written to warning log. */

long
fd_solcap_chunk_iter_next( fd_solcap_chunk_iter_t * iter );

/* fd_solcap_chunk_iter_err returns errno of last failure.  Returns 0
   if last failure was EOF, and non-zero otherwise.  Return value is
   undefined if no failure occurred yet. */

static inline int
fd_solcap_chunk_iter_err( fd_solcap_chunk_iter_t const * iter ) {
  return iter->err;
}

/* fd_solcap_chunk_iter_done returns 0 if there might be more chunks.
   Returns 1 if end-of-file was reached or read failure was encountered
   at last chunk. */

int
fd_solcap_chunk_iter_done( fd_solcap_chunk_iter_t const * iter );

/* fd_solcap_chunk_iter_item returns pointer to last successful chunk
   header read (using fd_solcap_chunk_iter_next()).  Lifetime of pointer
   is until next call to "next" or until lifetime of iter ends.  If no
   successful call to fd_solcap_chunk_iter_next was made yet, "chunk"
   field of return value is zero. */

static inline fd_solcap_chunk_t const *
fd_solcap_chunk_iter_item( fd_solcap_chunk_iter_t const * iter ) {
  return &iter->chunk;
}

/* fd_solcap_chunk_iter_find iterates through chunks until a chunk with
   the given magic is found.  Returns absolute file offset of chunk if
   chunk was found, and -1L if chunk was not found. */

static inline long
fd_solcap_chunk_iter_find( fd_solcap_chunk_iter_t * iter,
                           ulong                    magic ) {
  for(;;) {
    long chunk_gaddr = fd_solcap_chunk_iter_next( iter );
    if( FD_UNLIKELY( chunk_gaddr<0L ) )
      return -1L;
    if( FD_UNLIKELY( fd_solcap_chunk_iter_done( iter ) ) )
      return -1L;
    if( fd_solcap_chunk_iter_item( iter )->magic == magic )
      return chunk_gaddr;
  }
}

/* fd_solcap_read_bank_preimage reads and parses the bank preimage
   metadata blob.  chunk_goff is the file offset of the chunk containing
   the bank preimage.  hdr points to a copy of the corresponding chunk
   header. */

int
fd_solcap_read_bank_preimage( void *                    stream,
                              ulong                     chunk_goff,
                              fd_solcap_BankPreimage *  preimage,
                              fd_solcap_chunk_t const * hdr );

/* fd_solcap_find_account_table reads an account table meta and seeks
   the given (FILE *) like stream to the first account table row.
   acc_tbl_goff is the file offset of the chunk containing the account
   table.  On success, writes the account meta to *meta and returns 0.
   On failure, returns errno-like error code. */

int
fd_solcap_find_account_table( void *                       _file,
                              fd_solcap_AccountTableMeta * meta,
                              ulong                        acc_tbl_goff );

/* fd_solcap_includes_account_data returns 1 if a capture account chunk
   includes account data, and 0 otherwise.  Reasons for missing account
   data are that capture program deliberately excluded them, or that
   account data size is zero. */

static inline int
fd_solcap_includes_account_data( fd_solcap_AccountMeta const * meta ) {
  return (!!meta->data_coff) & (!!meta->data_sz);
}

/* fd_solcap_find_account reads an account meta.  If opt_data_off, sets
   *opt_data_off to the file offset to account data.  If account data
   size is zero or the capture does not include account data,
   *opt_data_off is undefined.  (Use fd_solcap_includes_account_data to
   check).  Returns 0 on success or errno-like on failure. */

int
fd_solcap_find_account( void *                          _file,
                        fd_solcap_AccountMeta *         meta,
                        ulong *                         opt_data_off,
                        fd_solcap_account_tbl_t const * rec,
                        ulong                           acc_tbl_goff );


FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_reader_h */

