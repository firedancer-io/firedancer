#include "fd_solcap_reader.h"
#include "fd_solcap_proto.h"
#include "../nanopb/pb_decode.h"

#if !FD_HAS_HOSTED
#error "fd_solcap_reader requires FD_HAS_HOSTED"
#endif

#include <errno.h>
#include <stdio.h>

fd_solcap_chunk_iter_t *
fd_solcap_chunk_iter_new( fd_solcap_chunk_iter_t * iter,
                          void *                   _stream ) {

  FILE * stream = (FILE *)_stream;

  long pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) ) {
    iter->err = errno;
    return iter;
  }

  *iter = (fd_solcap_chunk_iter_t) {
    .stream    = stream,
    .chunk     = {0},
    .chunk_off = 0UL,
    .chunk_end = (ulong)pos,
  };
  return iter;
}

long
fd_solcap_chunk_iter_next( fd_solcap_chunk_iter_t * iter ) {

  FILE * stream = (FILE *)iter->stream;

  long chunk_gaddr = (long)iter->chunk_end;
  if( FD_UNLIKELY( 0!=fseek( iter->stream, chunk_gaddr, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    iter->err = errno;
    return -1L;
  }
  iter->chunk_off = (ulong)chunk_gaddr;

  ulong n = fread( &iter->chunk, sizeof(fd_solcap_chunk_t), 1UL, stream );
  if( FD_UNLIKELY( n!=1UL ) ) {
    int err = ferror( stream );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fread failed (%d-%s)", errno, strerror( errno ) ));
      iter->err = err;
    }
    iter->err = 0;
    return -1L;
  }

  if( FD_UNLIKELY( ( !fd_solcap_is_chunk_magic( iter->chunk.magic )   )
                 | ( iter->chunk.total_sz < sizeof(fd_solcap_chunk_t) ) ) ) {
    FD_LOG_WARNING(( "invalid chunk (offset=%#lx magic=0x%016lx total_sz=%lu)",
                     chunk_gaddr, iter->chunk.magic, iter->chunk.total_sz ));
    iter->err = EPROTO;
    return -1L;
  }

  iter->chunk_end = (ulong)chunk_gaddr + iter->chunk.total_sz;

  return chunk_gaddr;
}

int
fd_solcap_chunk_iter_done( fd_solcap_chunk_iter_t const * iter ) {
  return feof( (FILE *)iter->stream ) || fd_solcap_chunk_iter_err( iter );
}


int
fd_solcap_read_bank_preimage( void *                    _file,
                              ulong                     chunk_goff,
                              fd_solcap_BankPreimage *  preimage,
                              fd_solcap_chunk_t const * hdr ) {

  if( FD_UNLIKELY( hdr->magic != FD_SOLCAP_V1_BANK_MAGIC ) )
    return EPROTO;

  /* Seek to Protobuf */
  FILE * file = (FILE *)_file;
  if( FD_UNLIKELY( 0!=fseek( file, (long)chunk_goff + hdr->meta_coff, SEEK_SET ) ) )
    return errno;

  /* Read into stack buffer */
  uchar buf[ FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT ];
  if( FD_UNLIKELY( hdr->meta_sz > FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT ) )
    return ENOMEM;
  if( FD_UNLIKELY( hdr->meta_sz != fread( buf, 1UL, hdr->meta_sz, file ) ) )
    return ferror( file );

  /* Decode */
  pb_istream_t stream = pb_istream_from_buffer( buf, hdr->meta_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_BankPreimage_fields, preimage ) ) ) {
    FD_LOG_WARNING(( "pb_decode failed (%s)", PB_GET_ERROR(&stream) ));
    return EPROTO;
  }

  return 0;
}

int
fd_solcap_find_account_table( void *                       _file,
                              fd_solcap_AccountTableMeta * meta,
                              ulong                        _chunk_goff ) {

  /* Read account table chunk header */
  long chunk_goff = (long)_chunk_goff;
  fd_solcap_chunk_t hdr[1];
  FILE * file = (FILE *)_file;
  if( FD_UNLIKELY( 0!=fseek( file, chunk_goff, SEEK_SET ) ) )
    return errno;
  if( FD_UNLIKELY( 1UL != fread( hdr, sizeof(fd_solcap_chunk_t), 1UL, file ) ) )
    return ferror( file );
  if( FD_UNLIKELY( hdr->magic != FD_SOLCAP_V1_ACTB_MAGIC ) )
    return EPROTO;

  /* Seek to Protobuf */
  if( FD_UNLIKELY( 0!=fseek( file, chunk_goff + hdr->meta_coff, SEEK_SET ) ) )
    return errno;

  /* Read into stack buffer */
  uchar buf[ FD_SOLCAP_ACTB_META_FOOTPRINT ];
  if( FD_UNLIKELY( hdr->meta_sz > FD_SOLCAP_ACTB_META_FOOTPRINT ) )
    return ENOMEM;
  if( FD_UNLIKELY( hdr->meta_sz != fread( buf, 1UL, hdr->meta_sz, file ) ) )
    return ferror( file );

  /* Decode */
  pb_istream_t stream = pb_istream_from_buffer( buf, hdr->meta_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_AccountTableMeta_fields, meta ) ) ) {
    FD_LOG_WARNING(( "pb_decode failed (%s)", PB_GET_ERROR(&stream) ));
    return EPROTO;
  }

  /* Seek to table */
  if( meta->account_table_coff ) {
    if( FD_UNLIKELY( 0!=fseek( file, chunk_goff + (long)meta->account_table_coff, SEEK_SET ) ) )
      return errno;
  }

  return 0;
}

int
fd_solcap_find_account( void *                          _file,
                        fd_solcap_AccountMeta *         meta,
                        ulong *                         opt_data_off,
                        fd_solcap_account_tbl_t const * rec,
                        ulong                           acc_tbl_goff ) {

  /* Read account chunk header */
  long chunk_goff = (long)acc_tbl_goff + rec->acc_coff;
  fd_solcap_chunk_t hdr[1];
  FILE * file = (FILE *)_file;
  if( FD_UNLIKELY( 0!=fseek( file, chunk_goff, SEEK_SET ) ) )
    return errno;
  if( FD_UNLIKELY( 1UL != fread( hdr, sizeof(fd_solcap_chunk_t), 1UL, file ) ) )
    return ferror( file );
  if( FD_UNLIKELY( hdr->magic != FD_SOLCAP_V1_ACCT_MAGIC ) )
    return EPROTO;

  /* Seek to Protobuf */
  if( FD_UNLIKELY( 0!=fseek( file, chunk_goff + hdr->meta_coff, SEEK_SET ) ) )
    return errno;

  /* Read into stack buffer */
  uchar buf[ FD_SOLCAP_ACCOUNT_META_FOOTPRINT ];
  if( FD_UNLIKELY( hdr->meta_sz > FD_SOLCAP_ACCOUNT_META_FOOTPRINT ) )
    return ENOMEM;
  if( FD_UNLIKELY( hdr->meta_sz != fread( buf, 1UL, hdr->meta_sz, file ) ) )
    return ferror( file );

  /* Decode */
  pb_istream_t stream = pb_istream_from_buffer( buf, hdr->meta_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_AccountMeta_fields, meta ) ) ) {
    FD_LOG_WARNING(( "pb_decode failed (%s)", PB_GET_ERROR(&stream) ));
    return EPROTO;
  }

  /* Seek to account data */
  if( fd_solcap_includes_account_data( meta ) && opt_data_off )
    *opt_data_off = (ulong)( chunk_goff + (long)meta->data_coff );

  return 0;
}
