#include "fd_solcap_writer.h"
#include "fd_solcap_proto.h"
#include "../../discof/capture/fd_capture_ctx.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>

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
  return mem;
}

void *
fd_solcap_writer_delete( fd_solcap_writer_t * writer ) {
  (void)writer;
  return NULL;
}

fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                          FILE *                  file ) {

  if( FD_UNLIKELY( !writer ) ) {
    FD_LOG_WARNING(( "NULL writer" ));
    return NULL;
  }
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }

  writer->file = file;

  long pos = ftell( file );
  if ( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }
  writer->stream_goff = (ulong)pos;

  fd_solcap_file_hdr_t file_hdr = {
    .block_type = FD_SOLCAP_V2_FILE_MAGIC, /* pcap section header magic */
    .block_len = sizeof(fd_solcap_file_hdr_t),
    .byte_order_magic = FD_SOLCAP_V2_BYTE_ORDER_MAGIC,
    .major_version = 0x00000001,
    .minor_version = 0x00000000,
    .section_len = -1UL,
    .block_len_redundant = sizeof(fd_solcap_file_hdr_t)
  };
  fwrite( &file_hdr, sizeof(fd_solcap_file_hdr_t), 1UL, file );

  fd_solcap_chunk_idb_hdr_t idb_hdr = {
    .block_type = SOLCAP_PCAPNG_BLOCK_TYPE_IDB,
    .block_len = sizeof(fd_solcap_chunk_idb_hdr_t),
    .link_type = SOLCAP_IDB_HDR_LINK_TYPE,
    .reserved = 0,
    .snap_len = SOLCAP_IDB_HDR_SNAP_LEN,
    .block_len_redundant = sizeof(fd_solcap_chunk_idb_hdr_t)
  };
  fwrite( &idb_hdr, sizeof(fd_solcap_chunk_idb_hdr_t), 1UL, file );

  return writer;
}

FILE*
fd_solcap_file_verify( fd_solcap_writer_t * writer ) {
  FILE * file = writer->file;
  if ( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }
  return file;
}

uint32_t
fd_solcap_write_account_hdr( fd_solcap_writer_t *         writer,
                              fd_solcap_buf_msg_t *           msg_hdr,
                              fd_solcap_account_update_hdr_t * account_update ) {
  FILE * file = fd_solcap_file_verify( writer );

  ulong data_sz = account_update->data_sz;

  uint32_t packet_len = (uint32_t)(sizeof(fd_solcap_chunk_int_hdr_t) +
                                    sizeof(fd_solcap_account_update_hdr_t) +
                                    data_sz);

  uint32_t unaligned_block_len = (uint32_t)(sizeof(fd_solcap_chunk_epb_hdr_t) +
                                   packet_len +
                                   sizeof(fd_solcap_chunk_ftr_t));

  uint32_t block_len = (uint32_t)((unaligned_block_len + 3UL) & ~3UL);

  fd_solcap_chunk_epb_hdr_t epb_hdr = {
    .block_type = SOLCAP_PCAPNG_BLOCK_TYPE_EPB,
    .block_len = block_len,
    .interface_id = 0,
    .timestamp_upper = 0,
    .timestamp_lower = 0,
    .captured_packet_len = packet_len,
    .original_packet_len = packet_len
  };
  fwrite( &epb_hdr, sizeof(fd_solcap_chunk_epb_hdr_t), 1UL, file );

  fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_ACCOUNT_HDR,
    .slot = (uint32_t)msg_hdr->slot,
    .txn_idx = msg_hdr->txn_idx
  };
  fwrite( &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t), 1UL, file );

  fwrite( account_update, sizeof(fd_solcap_account_update_hdr_t), 1UL, file );

  return block_len;
}

uint32_t
fd_solcap_write_account_data( fd_solcap_writer_t * writer,
                              void const *         data,
                              ulong                data_sz ) {
  FILE * file = fd_solcap_file_verify( writer );
  fwrite( data, data_sz, 1UL, file );
  return 0;
}


uint32_t
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               fd_solcap_buf_msg_t * msg_hdr,
                               fd_solcap_bank_preimage_t * bank_preimage ) {
   FILE * file = fd_solcap_file_verify( writer );

   uint32_t packet_len = (uint32_t)(sizeof(fd_solcap_chunk_int_hdr_t) +
                                     sizeof(fd_solcap_bank_preimage_t));

   uint32_t unaligned_block_len = (uint32_t)(sizeof(fd_solcap_chunk_epb_hdr_t) +
                                    packet_len +
                                    sizeof(fd_solcap_chunk_ftr_t));

  uint32_t block_len = (uint32_t)((unaligned_block_len + 3UL) & ~3UL);

   fd_solcap_chunk_epb_hdr_t epb_hdr = {
    .block_type = SOLCAP_PCAPNG_BLOCK_TYPE_EPB,
    .block_len = block_len,
    .interface_id = 0,
    .timestamp_upper = 0,
    .timestamp_lower = 0,
    .captured_packet_len = packet_len,
    .original_packet_len = packet_len
   };
   fwrite( &epb_hdr, sizeof(fd_solcap_chunk_epb_hdr_t), 1UL, file );

   fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = (uint32_t)msg_hdr->slot,
    .txn_idx = msg_hdr->txn_idx
   };
   fwrite( &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t), 1UL, file );

   fwrite( bank_preimage, sizeof(fd_solcap_bank_preimage_t), 1UL, file );

   return block_len;
}

uint32_t
fd_solcap_write_ftr( fd_solcap_writer_t * writer,
                     uint32_t             block_len_redundant ) {
  FILE * file = fd_solcap_file_verify( writer );
  long current_pos = ftell( file );
  uint32_t padding_needed = (-(current_pos) & 3);

  if (padding_needed > 0) {
    static const char zeros[4] = {0};
    fwrite(zeros, 1, padding_needed, file);
  }

  fd_solcap_chunk_ftr_t ftr = {
    .block_len_redundant = block_len_redundant
  };
  fwrite( &ftr, sizeof(fd_solcap_chunk_ftr_t), 1UL, file );
  return 0;
}
