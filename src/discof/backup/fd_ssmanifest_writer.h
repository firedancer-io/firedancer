#ifndef HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h
#define HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h

#include "../../flamenco/runtime/fd_bank.h"

#define FD_SSMANIFEST_BUF_MIN (32UL<<20)

struct fd_ssmanifest_writer {
  uint state;
  fd_bank_t const * bank;
};

typedef struct fd_ssmanifest_writer fd_ssmanifest_writer_t;

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * writer,
                           fd_bank_t const *        bank );

ulong
fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,
                            uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],
                            ulong buf_sz );

#endif /* HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h */
