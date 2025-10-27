#include "fd_solcap_writer.h"
#include "fd_solcap_proto.h"

#include <errno.h>
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

  off_t pos = lseek( fd, 0L, SEEK_SET );
  if( FD_UNLIKELY( pos < 0L ) ) {
    FD_LOG_WARNING(( "lseek failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  /* Write Section Header Block (SHB) - PCapNG file header */
  uint shb_size = (uint)(sizeof(fd_pcapng_shb_t) + 4U); /* +4 for redundant length */
  fd_pcapng_shb_t shb = {
    .block_type       = FD_PCAPNG_BLOCK_TYPE_SHB,
    .block_sz         = shb_size,
    .byte_order_magic = FD_PCAPNG_BYTE_ORDER_MAGIC,
    .version_major    = 1,
    .version_minor    = 0,
    .section_sz       = ULONG_MAX  /* -1 = unlimited */
  };
  FD_TEST( sizeof(fd_pcapng_shb_t) == (ulong)write(fd, &shb, sizeof(fd_pcapng_shb_t)) );
  /* Write redundant block length footer */
  FD_TEST( 4U == (uint)write(fd, &shb_size, 4U) );

  /* Write Interface Description Block (IDB) */
  uint idb_size = (uint)(sizeof(fd_pcapng_idb_t) + 4U); /* +4 for redundant length */
  fd_pcapng_idb_t idb = {
    .block_type = FD_PCAPNG_BLOCK_TYPE_IDB,
    .block_sz   = idb_size,
    .link_type  = SOLCAP_IDB_HDR_LINK_TYPE,
    ._pad_0a    = 0,
    .snap_len   = SOLCAP_IDB_HDR_SNAP_LEN
  };
  FD_TEST( sizeof(fd_pcapng_idb_t) == (ulong)write(fd, &idb, sizeof(fd_pcapng_idb_t)) );
  /* Write redundant block length footer */
  FD_TEST( 4U == (uint)write(fd, &idb_size, 4U) );

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

  uint unaligned_block_len = (uint)(sizeof(fd_pcapng_epb_t) +
                                 packet_len +
                                 4U); /* +4 for redundant length footer */

  uint block_len = (uint)((unaligned_block_len + 3UL) & ~3UL);

  fd_pcapng_epb_t epb = {
    .block_type = FD_PCAPNG_BLOCK_TYPE_EPB,
    .block_sz   = block_len,
    .if_idx     = 0,
    .ts_hi      = 0,
    .ts_lo      = 0,
    .cap_len    = packet_len,
    .orig_len   = packet_len
  };
  FD_TEST( sizeof(fd_pcapng_epb_t) == (ulong)write(fd, &epb, sizeof(fd_pcapng_epb_t)) );

  fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_ACCOUNT_HDR,
    .slot =       (uint)msg_hdr->slot,
    .txn_idx =    msg_hdr->txn_idx
  };
  FD_TEST( sizeof(fd_solcap_chunk_int_hdr_t) == (ulong)write(fd, &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t)) );

  FD_TEST( sizeof(fd_solcap_account_update_hdr_t) == (ulong)write(fd, account_update, sizeof(fd_solcap_account_update_hdr_t)) );

  return block_len;
}

uint
fd_solcap_write_account_data( fd_solcap_writer_t * writer,
                              void const *         data,
                              ulong                data_sz ) {
  int fd = writer->fd;
  FD_TEST( data_sz == (ulong)write(fd, data, data_sz) );
  return 0;
}


uint
fd_solcap_write_bank_preimage( fd_solcap_writer_t *        writer,
                               fd_solcap_buf_msg_t *       msg_hdr,
                               fd_solcap_bank_preimage_t * bank_preimage ) {
   int fd = writer->fd;

   uint packet_len = (uint)(sizeof(fd_solcap_chunk_int_hdr_t) +
                     sizeof(fd_solcap_bank_preimage_t));

   uint unaligned_block_len = (uint)(sizeof(fd_pcapng_epb_t) +
                              packet_len + 4U); /* +4 for redundant length footer */

  uint block_len = (uint)((unaligned_block_len + 3UL) & ~3UL);

   fd_pcapng_epb_t epb = {
    .block_type = FD_PCAPNG_BLOCK_TYPE_EPB,
    .block_sz   = block_len,
    .if_idx     = 0,
    .ts_hi      = 0,
    .ts_lo      = 0,
    .cap_len    = packet_len,
    .orig_len   = packet_len
   };
   FD_TEST( sizeof(fd_pcapng_epb_t) == (ulong)write(fd, &epb, sizeof(fd_pcapng_epb_t)) );

   fd_solcap_chunk_int_hdr_t int_hdr = {
    .block_type = SOLCAP_WRITE_BANK_PREIMAGE,
    .slot = (uint)msg_hdr->slot,
    .txn_idx = msg_hdr->txn_idx
   };
   FD_TEST( sizeof(fd_solcap_chunk_int_hdr_t) == (ulong)write(fd, &int_hdr, sizeof(fd_solcap_chunk_int_hdr_t)) );

   FD_TEST( sizeof(fd_solcap_bank_preimage_t) == (ulong)write(fd, bank_preimage, sizeof(fd_solcap_bank_preimage_t)) );

   return block_len;
}

uint
fd_solcap_write_ftr( fd_solcap_writer_t * writer,
                     uint                 block_len_redundant ) {
  int fd = writer->fd;
  off_t current_pos = lseek( fd, 0L, SEEK_CUR );
  FD_TEST( current_pos >= 0L );
  uint padding_needed = (-(uint)current_pos & 3);

  /* Write padding to align to 4-byte boundary */
  if( padding_needed > 0 ) {
    static const char zeros[4] = {0};
    FD_TEST( padding_needed == (uint)write(fd, zeros, padding_needed) );
  }

  /* Write redundant block length footer (4 bytes) */
  FD_TEST( 4U == (uint)write(fd, &block_len_redundant, 4U) );
  return 0;
}
