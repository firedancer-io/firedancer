#include "fd_solcap_writer.h"
#include "fd_solcap_proto.h"
#include "../nanopb/pb_encode.h"

#if !FD_HAS_HOSTED
#error "fd_solcap_writer requires FD_HAS_HOSTED"
#endif

#include <errno.h>
#include <stdio.h>

/* Note on suffixes:

    goff: file offset (as returned by fseek)
    foff: file offset from beginning of solcap stream
    coff: file offset from beginning of current chunk */

/* fd_solcap_writer is the state of a capture writer.  Currently, it
   is only able to capture the bank hash pre-image and chagned accounts.

   The writer progresses with each API call to the writer functions.

   Typically, the order is the following:

   - fd_solcap_writer_set_slot advances to the next slot.  If there was
     a previous slot in progress but not finished, discards buffers.
   - fd_solcap_write_account writes an account chunk and buffers an
     entry for the accounts table.
   - fd_solcap_write_bank_preimage flushes the buffered accounts table
     and writes the preimage chunk.  Slot is finished and ready for
     next iteration. */

struct fd_solcap_writer {
  FILE * file;

  /* Number of bytes between start of file and start of stream.
     Usually 0.  Non-zero if the bank capture is contained in some
     other file format. */
  ulong stream_goff;

  /* In-flight write of accounts table.
     account_idx==0UL implies no chunk header has been written yet.
     account_idx>=0UL implies AccountTable chunk write is pending.
     account_idx>=FD_SOLCAP_ACC_TBL_CNT implies that AccountTable is
     unable to fit records.  Table record will be skipped. */

  ulong                   slot;
  fd_solcap_account_tbl_t accounts[ FD_SOLCAP_ACC_TBL_CNT ];
  uint                    account_idx;
  ulong                   account_table_goff;

  ulong first_slot;
};

/* FTELL_BAIL calls ftell on the given file, and bails the current
   function with return code EIO if it fails. */

#define FTELL_BAIL( file )                      \
  (__extension__({                              \
    long n = ftell( (file) );                   \
    if( FD_UNLIKELY( n<0L ) ) {                 \
      FD_LOG_WARNING(( "ftell failed (%d-%s)",  \
        errno, strerror( errno ) ));            \
      return EIO;                               \
    }                                           \
    (ulong)n;                                   \
  }))

/* FSEEK_BAIL calls fseek on the given file, and bails the current
   function with return code EIO if it fails. */

#define FSEEK_BAIL( file, off, whence )         \
  (__extension__({                              \
    int err = fseek( (file), (off), (whence) ); \
    if( FD_UNLIKELY( err<0L ) ) {               \
      FD_LOG_WARNING(( "fseek failed (%d-%s)",  \
        errno, strerror( errno ) ));            \
      return EIO;                               \
    }                                           \
    0;                                          \
  }))

/* FWRITE_BAIL calls fwrite on the given file, and bails the current
   function with return code EIO if it fails. */

#define FWRITE_BAIL( ptr, sz, cnt, file )          \
  (__extension__({                                 \
    ulong _cnt = (cnt);                            \
    ulong n = fwrite( (ptr), (sz), _cnt, (file) ); \
    if( FD_UNLIKELY( n!=_cnt ) ) {                 \
      FD_LOG_WARNING(( "fwrite failed (%d-%s)",    \
        errno, strerror( errno ) ));               \
      return EIO;                                  \
    }                                              \
    0;                                             \
  }))

/* _skip_file writes zeros to the file */

static int
_skip_file( FILE * file,
            ulong  skip ) {
  if (skip == 0) return 0;

  uchar zero[ skip ];
  fd_memset( zero, 0, skip );

  FWRITE_BAIL( zero, 1UL, skip, file );
  return 0;
}

#define FSKIP_BAIL( file, skip )            \
  do {                                      \
    int err = _skip_file( (file), (skip) ); \
    if( FD_UNLIKELY( err!=0 ) ) return err; \
  } while(0)

/* _align_file pads file with zero up to meet given align requirement.
   align is a positive power of two. */

static int
_align_file( FILE * file,
             ulong  align ) {
  ulong pos  = FTELL_BAIL( file );
  ulong skip = fd_ulong_align_up( pos, align ) - pos;
  return _skip_file( file, skip );
}

#define FALIGN_BAIL( file, align )            \
  do {                                        \
    int err = _align_file( (file), (align) ); \
    if( FD_UNLIKELY( err!=0 ) ) return err;   \
  } while(0)


ulong
fd_solcap_writer_align( void ) {
  return alignof(fd_solcap_writer_t);
}

ulong
fd_solcap_writer_footprint( void ) {
  return sizeof(fd_solcap_writer_t);
}

fd_solcap_writer_t *
fd_solcap_writer_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  memset( mem, 0, sizeof(fd_solcap_writer_t) );
  return (fd_solcap_writer_t *)mem;
}

void *
fd_solcap_writer_delete( fd_solcap_writer_t * writer ) {

  if( FD_UNLIKELY( !writer ) ) return NULL;

  writer->file = NULL;
  return writer;
}


fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       void *               file ) {

  if( FD_UNLIKELY( !writer ) ) {
    FD_LOG_WARNING(( "NULL writer" ));
    return NULL;
  }
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }

  /* Leave space for file headers */

  long pos = ftell( file );
  if( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }
  ulong stream_goff = (ulong)pos;

  uchar zero[ FD_SOLCAP_FHDR_SZ ] = {0};
  ulong n = fwrite( zero, FD_SOLCAP_FHDR_SZ, 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  /* Init writer */

  *writer = (fd_solcap_writer_t) {
    .file        = (FILE *)file,
    .stream_goff = (ulong)stream_goff
  };

  return writer;
}

/* fd_solcap_writer_fini writes the file header. */

fd_solcap_writer_t *
fd_solcap_writer_fini( fd_solcap_writer_t * writer ) {

  if( FD_LIKELY( !writer ) ) return NULL;

  /* Remember stream cursor */

  long cursor = ftell( writer->file );
  if( FD_UNLIKELY( cursor<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  /* Construct file header */

  fd_solcap_FileMeta fmeta = {
    .first_slot       = writer->first_slot,
    .slot_cnt         = (ulong)fd_long_max( 0L, (long)writer->slot - (long)writer->first_slot ),
    .main_block_magic = FD_SOLCAP_V1_BANK_MAGIC,
  };

  uchar meta[ 128UL ];
  pb_ostream_t stream = pb_ostream_from_buffer( meta, sizeof(meta) );
  if( FD_UNLIKELY( !pb_encode( &stream, fd_solcap_FileMeta_fields, &fmeta ) ) ) {
    FD_LOG_WARNING(( "pb_encode failed (%s)", PB_GET_ERROR(&stream) ));
    return NULL;
  }

  fd_solcap_fhdr_t fhdr = {
    .magic       = FD_SOLCAP_V1_FILE_MAGIC,
    .chunk0_foff = FD_SOLCAP_FHDR_SZ,
    .meta_sz     = (uint)stream.bytes_written,
  };

  /* Write out file headers */

  if( FD_UNLIKELY( 0!=fseek( writer->file, (long)writer->stream_goff, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  if( FD_UNLIKELY( 1UL!=fwrite( &fhdr, sizeof(fd_solcap_fhdr_t), 1UL, writer->file ) ) ) {
    FD_LOG_WARNING(( "fwrite file header failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  if( FD_UNLIKELY( stream.bytes_written != fwrite( meta, 1UL, stream.bytes_written, writer->file ) ) ) {
    FD_LOG_WARNING(( "fwrite file meta failed (%d-%s)", ferror( writer->file ), strerror( ferror( writer->file ) ) ));
    return NULL;
  }

  /* Restore stream cursor */

  if( FD_UNLIKELY( 0!=fseek( writer->file, cursor, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  return writer;
}

/* fd_solcap_flush_account_table writes the buffered account table out
   to the stream. */

static int
fd_solcap_flush_account_table( fd_solcap_writer_t * writer ) {

  /* Only flush if at least one account present. */

  if( writer->account_idx == 0UL ) return 0;

  /* Skip if table was overflowed. */

  if( writer->account_idx >= FD_SOLCAP_ACC_TBL_CNT ) {
    writer->account_idx = 0UL;
    return 0;
  }

  /* Leave space for header */

  ulong chunk_goff = FTELL_BAIL( writer->file );
  FSKIP_BAIL( writer->file, sizeof(fd_solcap_chunk_t) );

  /* Translate account table to chunk-relative addressing */

  for( uint i=0U; i<writer->account_idx; i++ )
    writer->accounts[i].acc_coff -= (long)chunk_goff;

  /* Write account table (at beginning of chunk) */

  ulong account_table_coff = sizeof(fd_solcap_chunk_t);
  ulong account_table_cnt  = writer->account_idx;

  FWRITE_BAIL( writer->accounts,
               sizeof(fd_solcap_account_tbl_t),
               account_table_cnt,
               writer->file );

  /* Serialize account chunk metadata */

  ulong meta_goff = FTELL_BAIL( writer->file );
  fd_solcap_AccountTableMeta meta = {
    .slot               = writer->slot,
    .account_table_coff = account_table_coff,
    .account_table_cnt  = account_table_cnt
  };

  uchar encoded[ FD_SOLCAP_ACTB_META_FOOTPRINT ];
  pb_ostream_t stream = pb_ostream_from_buffer( encoded, sizeof(encoded) );
  if( FD_UNLIKELY( !pb_encode( &stream, fd_solcap_AccountTableMeta_fields, &meta ) ) ) {
    FD_LOG_WARNING(( "pb_encode failed (%s)", PB_GET_ERROR(&stream) ));
    return EPROTO;
  }

  FWRITE_BAIL( encoded, 1UL,  stream.bytes_written, writer->file );
  FALIGN_BAIL( writer->file, 8UL );

  /* Serialize chunk header */

  ulong chunk_end_goff = FTELL_BAIL( writer->file );

  fd_solcap_chunk_t chunk = {
    .magic     = FD_SOLCAP_V1_ACTB_MAGIC,
    .meta_coff = (uint)( meta_goff - chunk_goff ),
    .meta_sz   = (uint)stream.bytes_written,
    .total_sz  = chunk_end_goff - chunk_goff
  };

  /* Write out chunk */

  FSEEK_BAIL( writer->file, (long)chunk_goff, SEEK_SET );
  FWRITE_BAIL( &chunk,  sizeof(fd_solcap_chunk_t), 1UL, writer->file );

  /* Restore stream cursor */

  FSEEK_BAIL( writer->file, (long)chunk_end_goff, SEEK_SET );

  /* Wind up for next iteration */

  writer->account_table_goff = chunk_goff;
  writer->account_idx        = 0U;

  return 0;
}

int
fd_solcap_write_account( fd_solcap_writer_t *             writer,
                         void const *                     key,
                         fd_solana_account_meta_t const * meta,
                         void const *                     data,
                         ulong                            data_sz,
                         void const *                     hash ) {

  if( FD_LIKELY( !writer ) ) return 0;

  fd_solcap_account_tbl_t rec[1];
  memset( rec, 0, sizeof(fd_solcap_account_tbl_t) );
  memcpy( rec->key,  key,  32UL );
  memcpy( rec->hash, hash, 32UL );

  fd_solcap_AccountMeta meta_pb[1] = {{
    .lamports   = meta->lamports,
    .rent_epoch = meta->rent_epoch,
    .executable = meta->executable,
    .data_sz    = data_sz,
  }};
  memcpy( meta_pb->owner, meta->owner, 32UL );

  return fd_solcap_write_account2( writer, rec, meta_pb, data, data_sz );
}

int
fd_solcap_write_account2( fd_solcap_writer_t *             writer,
                          fd_solcap_account_tbl_t const *  tbl,
                          fd_solcap_AccountMeta *          meta_pb,
                          void const *                     data,
                          ulong                            data_sz ) {

  if( FD_LIKELY( !writer ) ) return 0;

  /* Locate chunk */

  ulong chunk_goff = FTELL_BAIL( writer->file );

  /* Write data */

  ulong data_coff = sizeof(fd_solcap_chunk_t);
  FSKIP_BAIL ( writer->file, data_coff );
  FWRITE_BAIL( data, 1UL, data_sz, writer->file );
  FALIGN_BAIL( writer->file, 8UL );

  /* Serialize account meta */

  ulong meta_goff = FTELL_BAIL( writer->file );

  meta_pb->slot      = writer->slot;
  meta_pb->data_coff = (long)data_coff;
  meta_pb->data_sz   = data_sz;

  uchar meta_pb_enc[ FD_SOLCAP_ACCOUNT_META_FOOTPRINT ];
  pb_ostream_t stream = pb_ostream_from_buffer( meta_pb_enc, sizeof(meta_pb_enc) );
  FD_TEST( pb_encode( &stream, fd_solcap_AccountMeta_fields, meta_pb ) );

  /* Write account meta */

  ulong meta_coff = meta_goff - chunk_goff;
  FWRITE_BAIL( meta_pb_enc, 1UL, stream.bytes_written, writer->file );
  FALIGN_BAIL( writer->file, 8UL );

  /* Remember account table entry */

  if( writer->account_idx < FD_SOLCAP_ACC_TBL_CNT ) {
    fd_solcap_account_tbl_t * account = &writer->accounts[ writer->account_idx ];
    memcpy( account, tbl, sizeof(fd_solcap_account_tbl_t) );

    /* Since we don't yet know the final position of the account table,
       we temporarily store a global offset.  This will later get
       converted into a chunk offset. */
    account->acc_coff = (long)chunk_goff;
  }

  /* Serialize chunk header */

  ulong chunk_end_goff = FTELL_BAIL( writer->file );

  fd_solcap_chunk_t chunk = {
    .magic     = FD_SOLCAP_V1_ACCT_MAGIC,
    .meta_coff = (uint)meta_coff,
    .meta_sz   = (uint)stream.bytes_written,
    .total_sz  = chunk_end_goff - chunk_goff
  };

  /* Write out chunk */

  FSEEK_BAIL( writer->file, (long)chunk_goff, SEEK_SET );
  FWRITE_BAIL( &chunk, sizeof(fd_solcap_chunk_t), 1UL, writer->file );

  /* Restore stream cursor */

  FSEEK_BAIL( writer->file, (long)chunk_end_goff, SEEK_SET );

  /* Wind up for next iteration */

  writer->account_idx += 1U;

  return 0;
}

void
fd_solcap_writer_set_slot( fd_solcap_writer_t * writer,
                          ulong                slot ) {

  if( FD_LIKELY( !writer ) ) return;

  /* Discard account table buffer */
  writer->account_table_goff = 0UL;
  writer->account_idx        = 0UL;
  writer->slot               = slot;
}

int
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               void const *         bank_hash,
                               void const *         prev_bank_hash,
                               void const *         account_delta_hash,
                               void const *         poh_hash,
                               ulong                signature_cnt ) {

  if( FD_LIKELY( !writer ) ) return 0;

  fd_solcap_BankPreimage preimage_pb[1] = {{0}};
  preimage_pb->signature_cnt = signature_cnt;
  preimage_pb->account_cnt   = writer->account_idx;
  memcpy( preimage_pb->bank_hash,          bank_hash,          32UL );
  memcpy( preimage_pb->prev_bank_hash,     prev_bank_hash,     32UL );
  memcpy( preimage_pb->account_delta_hash, account_delta_hash, 32UL );
  memcpy( preimage_pb->poh_hash,           poh_hash,           32UL );

  return fd_solcap_write_bank_preimage2( writer, preimage_pb );
}


int
fd_solcap_write_bank_preimage2( fd_solcap_writer_t *     writer,
                                fd_solcap_BankPreimage * preimage_pb ) {

  if( FD_LIKELY( !writer ) ) return 0;

  int err = fd_solcap_flush_account_table( writer );
  if( FD_UNLIKELY( err!=0 ) ) return err;

  /* Leave space for header */

  ulong chunk_goff = FTELL_BAIL( writer->file );
  FSKIP_BAIL( writer->file, sizeof(fd_solcap_chunk_t) );

  /* Fixup predefined entries */

  preimage_pb->slot               = writer->slot;
  if( writer->account_table_goff ) {
    preimage_pb->account_cnt        = writer->account_idx;
    preimage_pb->account_table_coff = (long)writer->account_table_goff - (long)chunk_goff;
  }

  /* Serialize bank preimage */

  uchar preimage_pb_enc[ FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT ] = {0};
  pb_ostream_t stream = pb_ostream_from_buffer( preimage_pb_enc, sizeof(preimage_pb_enc) );
  FD_TEST( pb_encode( &stream, fd_solcap_BankPreimage_fields, preimage_pb ) );
  ulong meta_sz = stream.bytes_written;

  FWRITE_BAIL( preimage_pb_enc, 1UL, meta_sz, writer->file );
  FALIGN_BAIL( writer->file, 8UL );
  ulong chunk_end_goff = FTELL_BAIL( writer->file );

  /* Serialize chunk header */

  fd_solcap_chunk_t chunk = {
    .magic     = FD_SOLCAP_V1_BANK_MAGIC,
    .meta_coff = (uint)sizeof(fd_solcap_chunk_t),
    .meta_sz   = (uint)meta_sz,
    .total_sz  = chunk_end_goff - chunk_goff
  };

  /* Write out chunk */

  FSEEK_BAIL( writer->file, (long)chunk_goff, SEEK_SET );
  FWRITE_BAIL( &chunk, sizeof(fd_solcap_chunk_t), 1UL, writer->file );

  /* Restore stream cursor */

  FSEEK_BAIL( writer->file, (long)chunk_end_goff, SEEK_SET );

  return 0;
}
