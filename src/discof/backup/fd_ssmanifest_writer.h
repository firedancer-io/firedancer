#ifndef HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h
#define HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h

/* fd_ssmanifest_writer.h provides streaming serialization of a Solana
   snapshot manifest. */

#include "../../flamenco/runtime/fd_bank.h"

struct fd_ssmanifest_writer {
  uint              state;
  fd_bank_t const * bank;
};

typedef struct fd_ssmanifest_writer fd_ssmanifest_writer_t;

/* fd_ssmanifest_writer_init creates a new snapshot manifest writer.
   Guaranteed to succeed for a valid bank. */

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * writer,
                           fd_bank_t const *        bank );

/* fd_snap_manifest_serialize serializes up to buf_sz worth of snapshot
   manifest data into out_buf.  Returns the number of bytes written.
   Returns 0UL if the manifest was fully serialized out.  Typical usage:

     uchar out_buf[ FD_SSMANIFEST_BUF_MIN ];
     for(;;) {
       ulong sz = fd_snap_manifest_serialize( enc, out_buf, sizeof(out_buf) );
       if( !sz ) break;
       fd_io_write( ... ); // write out chunk
     }

   Produces 1 GiB-ish data for a mainnet snapshot. */

#define FD_SSMANIFEST_BUF_MIN (32UL<<20)
ulong
fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,
                            uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],
                            ulong buf_sz );

/* fd_snapshot_manifest_serialized_sz returns the total amount of data
   that fd_snap_manifest_serialize would produce for the given bank. */

ulong
fd_snap_manifest_serialized_sz( fd_bank_t const * bank );

#endif /* HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h */
