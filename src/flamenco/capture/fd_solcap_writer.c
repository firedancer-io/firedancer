#include "fd_solcap_writer.h"
#include "fd_solcap_proto.h"

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

ulong
fd_solcap_writer_align( void ) {
  return alignof(fd_solcap_writer_t);
}

ulong
fd_solcap_writer_footprint( void ) {
  return sizeof(fd_solcap_writer_t);
}

fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       int                  fd ) {

  if( FD_UNLIKELY( !writer ) ) {
    FD_LOG_WARNING(( "NULL writer" ));
    return NULL;
  }
  if( FD_UNLIKELY( fd < 0 ) ) {
    FD_LOG_WARNING(( "invalid file descriptor" ));
    return NULL;
  }

  writer->fd = fd;

  off_t pos = lseek( fd, 0L, SEEK_CUR );
  if( FD_UNLIKELY( pos < 0L ) ) {
    FD_LOG_WARNING(( "lseek failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }
  writer->stream_goff = (ulong)pos;

  fd_solcap_file_hdr_t file_hdr = {
    .block_type          = FD_SOLCAP_V2_FILE_MAGIC, /* pcap section header magic */
    .block_len           = sizeof(fd_solcap_file_hdr_t),
    .byte_order_magic    = FD_SOLCAP_V2_BYTE_ORDER_MAGIC,
    .major_version       = 0x00000001,
    .minor_version       = 0x00000000,
    .section_len         = -1UL,
    .block_len_redundant = sizeof(fd_solcap_file_hdr_t)
  };
  FD_TEST(sizeof(fd_solcap_file_hdr_t) == write(fd, &file_hdr, sizeof(fd_solcap_file_hdr_t)));

  fd_solcap_chunk_idb_hdr_t idb_hdr = {
    .block_type          = SOLCAP_PCAPNG_BLOCK_TYPE_IDB,
    .block_len           = sizeof(fd_solcap_chunk_idb_hdr_t),
    .link_type           = SOLCAP_IDB_HDR_LINK_TYPE,
    .reserved            = 0,
    .snap_len            = SOLCAP_IDB_HDR_SNAP_LEN,
    .block_len_redundant = sizeof(fd_solcap_chunk_idb_hdr_t)
  };
  FD_TEST(sizeof(fd_solcap_chunk_idb_hdr_t) == write(fd, &idb_hdr, sizeof(fd_solcap_chunk_idb_hdr_t)));

  return writer;
}

uint
fd_solcap_write_account_hdr( fd_solcap_writer_t *             writer,
                             fd_solcap_buf_msg_t *            msg_hdr,
                             fd_solcap_account_update_hdr_t * account_update ) {
  int fd = writer->fd;

  ulong data_sz = account_update->data_sz;

  uint packet_len = (uint)(sizeof(fd_solcap_chunk_int_hdr_t) +
                        sizeof(fd_solcap_account_update_hdr_t) +
                        data_sz);

  uint unaligned_block_len = (uint)(sizeof(fd_solcap_chunk_epb_hdr_t) +
                                 packet_len +
                                 sizeof(fd_solcap_chunk_ftr_t));

  uint block_len = (uint)((unaligned_block_len + 3UL) & ~3UL);

  fd_solcap_chunk_epb_hdr_t epb_hdr = {
    .block_type          = SOLCAP_PCAPNG_BLOCK_TYPE_EPB,
    .block_len           = block_len,
    .interface_id        = 0,
    .timestamp_upper     = 0,
    .timestamp_lower     = 0,
    .captured_packet_len = packet_len,
    .original_packet_len = packet_len
  };
  FD_TEST(sizeof(fd_solcap_chunk_epb_hdr_t) == write(fd, &epb_hdr, sizeof(fd_solcap_chunk_epb_hdr_t)));

  fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_ACCOUNT_HDR,
    .slot =       (uint)msg_hdr->slot,
    .txn_idx =    msg_hdr->txn_idx
  };
  FD_TEST(sizeof(fd_solcap_chunk_int_hdr_t) == write(fd, &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t)));

  FD_TEST(sizeof(fd_solcap_account_update_hdr_t) == write(fd, account_update, sizeof(fd_solcap_account_update_hdr_t)));

  return block_len;
}

uint
fd_solcap_write_account_data( fd_solcap_writer_t * writer,
                              void const *         data,
                              ulong                data_sz ) {
  int fd = writer->fd;
  FD_TEST(data_sz == (ulong)write(fd, data, data_sz));
  return 0;
}


uint
fd_solcap_write_bank_preimage( fd_solcap_writer_t *        writer,
                               fd_solcap_buf_msg_t *       msg_hdr,
                               fd_solcap_bank_preimage_t * bank_preimage ) {
   int fd = writer->fd;

   uint packet_len = (uint)(sizeof(fd_solcap_chunk_int_hdr_t) +
                         sizeof(fd_solcap_bank_preimage_t));

   uint unaligned_block_len = (uint)(sizeof(fd_solcap_chunk_epb_hdr_t) +
                                  packet_len +
                                  sizeof(fd_solcap_chunk_ftr_t));

  uint block_len = (uint)((unaligned_block_len + 3UL) & ~3UL);

   fd_solcap_chunk_epb_hdr_t epb_hdr = {
    .block_type          = SOLCAP_PCAPNG_BLOCK_TYPE_EPB,
    .block_len           = block_len,
    .interface_id        = 0,
    .timestamp_upper     = 0,
    .timestamp_lower     = 0,
    .captured_packet_len = packet_len,
    .original_packet_len = packet_len
   };
   FD_TEST(sizeof(fd_solcap_chunk_epb_hdr_t) == write(fd, &epb_hdr, sizeof(fd_solcap_chunk_epb_hdr_t)));

   fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = (uint)msg_hdr->slot,
    .txn_idx = msg_hdr->txn_idx
   };
   FD_TEST(sizeof(fd_solcap_chunk_int_hdr_t) == write(fd, &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t)));

   FD_TEST(sizeof(fd_solcap_bank_preimage_t) == write(fd, bank_preimage, sizeof(fd_solcap_bank_preimage_t)));

   return block_len;
}

uint
fd_solcap_write_ftr( fd_solcap_writer_t * writer,
                     uint                 block_len_redundant ) {
  int fd = writer->fd;
  off_t current_pos = lseek( fd, 0L, SEEK_CUR );
  FD_TEST( current_pos >= 0L );
  uint padding_needed = (-(uint)current_pos & 3);

  if (padding_needed > 0) {
    static const char zeros[4] = {0};
    FD_TEST(padding_needed == write(fd, zeros, padding_needed));
  }

  fd_solcap_chunk_ftr_t ftr = {
    .block_len_redundant = block_len_redundant
  };
  FD_TEST(sizeof(fd_solcap_chunk_ftr_t) == write(fd, &ftr, sizeof(fd_solcap_chunk_ftr_t)));
  return 0;
}
