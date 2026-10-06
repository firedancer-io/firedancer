#ifndef HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h
#define HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h

/* fd_ssmanifest_writer.h provides streaming serialization of a Solana
   snapshot manifest. */

#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"

/* fd_ssmanifest_vote_account_t is a vote account of the stakes cache:
   one a stake delegation points at.  Keyed by pubkey in a fixed size
   hash map while init collects them; init then packs the valid ones
   into [0,vote_account_cnt). */

struct fd_ssmanifest_vote_account {
  fd_pubkey_t pubkey;
  uint        hash;
  uint        data_len;
  ulong       stake;
};

typedef struct fd_ssmanifest_vote_account fd_ssmanifest_vote_account_t;

#define FD_SSMANIFEST_VOTE_ACCOUNT_LG_SLOT_CNT (17) /* 2*FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS keys, fill ratio 0.5 */

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
  uint        state;
  fd_bank_t * bank;
  fd_pubkey_t leader; /* slot leader of the bank */
  uchar       epoch_idx;
  uchar       epoch_cnt;
  uint        vote_cnt;
  uint        vote_idx;
  ulong       total_stake;
  ulong       serialized_sz;
  uchar       vote_stakes_iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN)));
  fd_ssmanifest_epoch_map_t epoch_map[ FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN ];

  /* stakes cache */
  fd_accdb_t *                 accdb;
  fd_accdb_fork_id_t           accdb_fork_id;
  fd_stake_delegations_t *     stake_delegations;
  fd_stake_history_t           stake_history; /* view into the bank's sysvar cache */
  ulong                        vote_account_cnt;
  ulong                        vote_account_idx;
  ulong                        stake_delegation_cnt;
  ulong                        stake_delegation_idx;
  fd_stake_delegations_iter_t  stake_delegation_iter;
  fd_ssmanifest_vote_account_t vote_account[ 1UL<<FD_SSMANIFEST_VOTE_ACCOUNT_LG_SLOT_CNT ];
};

typedef struct fd_ssmanifest_writer fd_ssmanifest_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_ssmanifest_writer_init creates a new snapshot manifest writer.
   leader is the slot leader of bank.  Briefly views the root of
   stake_delegations to collect the vote accounts of the stakes cache
   and count the delegations, then reads those and the epoch stakes
   vote accounts from accdb at accdb_fork_id.
   fd_snap_manifest_serialize reads the stakes cache accounts again and
   views the root once per chunk of delegations it writes.  acc_data is
   scratch of at least FD_RUNTIME_ACC_SZ_MAX bytes.  Sets
   writer->serialized_sz. */

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * writer,
                           fd_bank_t *              bank,
                           fd_pubkey_t const *      leader,
                           fd_accdb_t *             accdb,
                           fd_accdb_fork_id_t       accdb_fork_id,
                           fd_stake_delegations_t * stake_delegations,
                           uchar *                  acc_data );

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

/* Each stakes cache vote account entry is pubkey (32) + stake (8) +
   lamports (8) + data_len (8) + owner (32) + executable (1) +
   rent_epoch (8) = 97 bytes plus the account data, at most
   FD_VOTE_STATE_V4_SZ.  The data is read straight into the output
   buffer, and a read needs FD_RUNTIME_ACC_SZ_MAX of room whatever the
   account's size. */

#define FD_SSMANIFEST_VOTE_ACCOUNT_HDR_SZ     (97UL)
#define FD_SSMANIFEST_VOTE_ACCOUNTS_PER_CHUNK ((FD_SSMANIFEST_BUF_MIN-FD_RUNTIME_ACC_SZ_MAX)/(FD_SSMANIFEST_VOTE_ACCOUNT_HDR_SZ+FD_VOTE_STATE_V4_SZ))

/* Each stakes cache delegation entry is the stake account's pubkey,
   then its delegation as laid out in the stake account. */

#define FD_SSMANIFEST_STAKE_DELEGATION_SZ         (sizeof(fd_pubkey_t)+sizeof(fd_delegation_t))
#define FD_SSMANIFEST_STAKE_DELEGATIONS_PER_CHUNK (FD_SSMANIFEST_BUF_MIN/FD_SSMANIFEST_STAKE_DELEGATION_SZ)

ulong
fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,
                            uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],
                            ulong buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_ssmanifest_writer_h */
