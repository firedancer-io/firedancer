#ifndef HEADER_fd_src_discof_restore_utils_fd_ssctrl_h
#define HEADER_fd_src_discof_restore_utils_fd_ssctrl_h

#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"

/* The snapshot tiles have a somewhat involved state machine, which is
   controlled by snaprd.  Imagine first the following sequence:

    1. snaprd is reading a full snapshot from the network and sends some
       data to snapdc to be decompressed.
    2. snaprd hits a network error, and resets the connection to a new
       peer.
    3. The decompressor fails on data from the old peer, and sends a
       malformed message to snaprd.
    4. snaprd receives the malformed message, and abandons the new
       connection, even though it was not malformed.

   There are basically two ways to prevent this.  Option A is the tiles
   can pass not just control messages to one another, but also tag them
   with some xid indicating which "attempt" the control message is for.

   This is pretty hard to reason about, and the state machine can grow
   quite complicated.

   There's an easier way: the tiles just are fully synchronized with
   snaprd.  Whatever "attempt" snaprd is on, we ensure all other tiles
   are on it too.  This means when any tile fails a snapshot, all tiles
   must fail it and fully flush all frags in the pipeline before snaprd
   can proceed with a new attempt.

   The control flow then is basically,

     1. All tiles start assuming we are reading the full snapshot.
     2. If any tile fails the snapshot, it sends a MALFOREMD message
        to snaprd.  Snaprd then sends a RESET message to all tiles.
     3. Any control message, including a RESET, send by snaprd must be
        acknowledged by all other tiles in the snapshot pipeline before
        snaprd can proceed with the next step.

   The keeps the tiles in lockstep, and simplifies the state machine to
   a manageable level. */

#define FD_SNAPSHOT_MSG_DATA                   (0UL) /* Fragment represents some snapshot data */

#define FD_SNAPSHOT_MSG_CTRL_RESET_FULL        (1UL) /* Reset to start loading a fresh full snapshot */
#define FD_SNAPSHOT_MSG_CTRL_EOF_FULL          (2UL) /* Full snapshot data is done, incremental data starting now */
#define FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL (3UL) /* Incremental data being retried, start incremental over */
#define FD_SNAPSHOT_MSG_CTRL_DONE              (4UL) /* Snapshot load is over, data is finished for this tile */
#define FD_SNAPSHOT_MSG_CTRL_SHUTDOWN          (5UL) /* All tiles have acknowledged snapshot load is done, can now shutdown */

#define FD_SNAPSHOT_MSG_CTRL_ACK               (6UL) /* Sent from tiles back to snaprd, meaning they ACK whatever control message was pending */
#define FD_SNAPSHOT_MSG_CTRL_MALFORMED         (7UL) /* Sent from tiles back to snaprd, meaning they consider the current snapshot malformed */

/* The following message signatures define the sequence of control and
   data messages between the snapin and snaplt tile.  The snaplt tile
   does not participate in control messages between snaprd, snapdc, and
   snapin.  It acts as a hashing accelerator for snapin. */
#define FD_SNAPSHOT_HASH_MSG_RESET             (8UL)  /* Indicates snapin has a new account stream incoming */
#define FD_SNAPSHOT_HASH_MSG_SUB               (9UL)  /* Indicates snapin has encountered a duplicate account whose hash must be subtracted */
#define FD_SNAPSHOT_HASH_MSG_ACCOUNT_HDR       (10UL) /* Indicates snapin has encountered a new account metadata */
#define FD_SNAPSHOT_HASH_MSG_ACCOUNT_DATA      (11UL) /* Account data that is sent as snapin processes a new account */
#define FD_SNAPSHOT_HASH_MSG_FINI              (12UL) /* Indicates the account stream from snapin is done, awaiting hash result */
#define FD_SNAPSHOT_HASH_MSG_RESULT            (13UL) /* Hash result sent from snaplt to snapin */
#define FD_SNAPSHOT_HASH_MSG_SHUTDOWN          (14UL) /* Snapin is shutting down, snaplt can shutdown too */

#define FD_MAX_SNAPLT_TILES (16UL)

/* fd_snapshot_account is the contents of the
   SNAPSHOT_HASH_MSG_ACCOUNT_HDR message.  It contains account metadata
   that is contained in the accounts hash. */
struct fd_snapshot_account {
  uchar   pubkey[ FD_HASH_FOOTPRINT ];
  uchar   owner[ FD_HASH_FOOTPRINT ];
  ulong   lamports;
  uchar   executable;
  ulong   data_len;
};
typedef struct fd_snapshot_account fd_snapshot_account_t;

/* fd_snapshot_account_init initializes a fd_snapshot_account_t struct
   with the appropriate account metadata fields. */
static inline void
fd_snapshot_account_init( fd_snapshot_account_t *  account,
                           uchar const             pubkey[ FD_HASH_FOOTPRINT ],
                           uchar const             owner[ FD_PUBKEY_FOOTPRINT ],
                           ulong                   lamports,
                           uchar                   executable,
                           ulong                   data_len ) {
  fd_memcpy( account->pubkey, pubkey, FD_HASH_FOOTPRINT );
  fd_memcpy( account->owner,  owner,  FD_PUBKEY_FOOTPRINT );
  account->lamports   = lamports;
  account->executable = executable;
  account->data_len   = data_len;
}

/* fd_snapshot_existing_account is the contents of the
   SNAPSHOT_HASH_MSG_SUB message.  It contains a fd_snapshot_account_t
   header and the corresponding account data in a single message.

   For simplicity and conformance to burst limitations in snapin, the
   entire duplicate account is sent in one message (one frag).  Consider
   caching the lthash of the duplicate account so we do not have to
   send the entire account over. */
struct fd_snapshot_existing_account {
  fd_snapshot_account_t hdr;
  uchar                 data[ FD_RUNTIME_ACC_SZ_MAX ];
};
typedef struct fd_snapshot_existing_account fd_snapshot_existing_account_t;

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssctrl_h */
