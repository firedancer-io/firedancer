#ifndef HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h
#define HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h

/* fd_ssmanifest_writer.h provides streaming serialization of a Solana
   snapshot manifest. */

#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_bank.h"

/* fd_ssmanifest_epoch_vote_t is a vote account of an epoch stakes set
   that has an authorized voter for the set's epoch.  Agave lists these
   per node (node_id_to_vote_accounts) and per voter
   (epoch_authorized_voters) next to the set. */

struct fd_ssmanifest_epoch_vote {
  fd_pubkey_t vote;
  fd_pubkey_t node;
  fd_pubkey_t voter;
  ulong       stake;
};

typedef struct fd_ssmanifest_epoch_vote fd_ssmanifest_epoch_vote_t;

struct fd_ssmanifest_epoch_map {
  ulong                      vote_cnt;
  ulong                      node_cnt; /* distinct nodes in vote */
  fd_ssmanifest_epoch_vote_t vote[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ]; /* sorted by node */
};

typedef struct fd_ssmanifest_epoch_map fd_ssmanifest_epoch_map_t;

struct fd_ssmanifest_writer {
  uint                       state;
  fd_bank_t *                bank;
  fd_pubkey_t                leader; /* slot leader of the bank */
  fd_epoch_credits_t const * epoch_credits;
  ulong                      epoch_credits_cnt;
  uchar       epoch_idx;
  uchar       epoch_cnt;
  uint        vote_cnt;
  uint        vote_idx;
  ulong       total_stake;
  ulong       serialized_sz;
  uchar       vote_stakes_iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN)));
  fd_ssmanifest_epoch_map_t epoch_map[ FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN ];
};

typedef struct fd_ssmanifest_writer fd_ssmanifest_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_ssmanifest_writer_init creates a new snapshot manifest writer.
   leader is the slot leader of bank.  epoch_credits points to the
   epoch_credits_cnt epoch credits of bank, which must stay valid until
   the manifest is serialized.  Reads the vote account of every epoch
   stakes entry from accdb at accdb_fork_id to fill the epoch maps.
   acc_data is scratch of at least FD_RUNTIME_ACC_SZ_MAX bytes.  Sets
   writer->serialized_sz.  Guaranteed to succeed for a valid bank. */

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t *   writer,
                           fd_bank_t *                bank,
                           fd_pubkey_t const *        leader,
                           fd_epoch_credits_t const * epoch_credits,
                           ulong                      epoch_credits_cnt,
                           fd_accdb_t *               accdb,
                           fd_accdb_fork_id_t         accdb_fork_id,
                           uchar *                    acc_data );

/* fd_snap_manifest_serialize serializes up to buf_sz worth of snapshot
   manifest data into out_buf.  Returns the number of bytes written.
   Returns 0UL if the manifest was fully serialized out, after which
   the writer is ready to serialize it again.  Typical usage:

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h */
