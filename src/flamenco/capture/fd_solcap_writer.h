#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_writer_h

#include "fd_solcap_proto.h"


/* fd_solcap_writer_t is a writer utility for solcap files.

    Each soclap write function is responsible for encoding and writing
    out a specific type of chunk. They provide both a header, which
    contains information about type of chunk, size, and slot number,
    and the chunk data.

    Note: The functionality is limited to the writing of solcap v2 files
    Nishk (TODO): Write docs for solcap writer
*/

FD_PROTOTYPES_BEGIN

#define SOLCAP_WRITE_ACCOUNT_DATA_MTU (131072UL)

typedef struct fd_solcap_writer {
  int   fd;
  ulong stream_goff;
} fd_solcap_writer_t;

ulong
fd_solcap_writer_align( void );

ulong
fd_solcap_writer_footprint( void );

fd_solcap_writer_t *
fd_solcap_writer_init(  fd_solcap_writer_t * writer,
                        int                  fd );

uint
fd_solcap_write_account_hdr( fd_solcap_writer_t *              writer,
                              fd_solcap_buf_msg_t *            msg_hdr,
                              fd_solcap_account_update_hdr_t * account_update );

uint
fd_solcap_write_account_data( fd_solcap_writer_t * writer,
                              void const *         data,
                              ulong                data_sz );

uint
fd_solcap_write_bank_preimage( fd_solcap_writer_t *        writer,
                               fd_solcap_buf_msg_t *       msg_hdr,
                               fd_solcap_bank_preimage_t * bank_preimage );

uint
fd_solcap_write_ftr( fd_solcap_writer_t * writer,
                     uint                 block_len_redundant );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_writer_h */
