#ifndef HEADER_fd_src_discof_restore_utils_fd_ssctrl_h
#define HEADER_fd_src_discof_restore_utils_fd_ssctrl_h

#include "../../../util/net/fd_net_headers.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"

/* The snapshot tiles have a somewhat involved state machine, which is
   controlled by snapct.  Imagine first the following sequence:

    1. snapct is reading a full snapshot from the network and sends some
       data to snapdc to be decompressed.
    2. snapct hits a network error, and resets the connection to a new
       peer.
    3. The decompressor fails on data from the old peer, and sends a
       malformed message to snapct.
    4. snapct receives the malformed message, and abandons the new
       connection, even though it was not malformed.

   There are basically two ways to prevent this.  Option A is the tiles
   can pass not just control messages to one another, but also tag them
   with some xid indicating which "attempt" the control message is for.

   This is pretty hard to reason about, and the state machine can grow
   quite complicated.

   There's an easier way: the tiles just are fully synchronized with
   snapct.  Whatever "attempt" snapct is on, we ensure all other tiles
   are on it too.  This means when any tile fails a snapshot, all tiles
   must fail it and fully flush all frags in the pipeline before snapct
   can proceed with a new attempt.

   The control flow then is basically,

     1. All tiles start in the IDLE state.
     2. snapct initializes the pipeline by sending an INIT message.
        Each tile enters the PROCESSING state and then forwards the INIT
        message down the pipeline.  When snapct receives this INIT
        message, the entire pipeline is in PROCESSING state.
     3. Tiles continue to process data / frags as applicable.  If an
        error occurs, the tile enters the ERROR state and also sends an
        ERROR message downstream.  All downstream tiles also enter the
        ERROR state and forward the message.  Note that upstream tiles
        will not be in an ERROR state and will continue producing frags.
        When snapct receives the ERROR message, it will send a FAIL
        message.  snapct then waits for this FAIL message to be
        progagated through the pipeline and received back.  It then
        knows that all tiles are synchonized back in an IDLE state and
        it can try again with a new INIT.
     4. Once snapct detects that the processing is finished, it sends
        a DONE message through the pipeline and waits for it to be
        received back.  We then either move on to the incremental
        snapshot, or shut down the whole pipeline.

   The keeps the tiles in lockstep, and simplifies the state machine to
   a manageable level.

   It is a strict requirement that all tiles in the pipeline eventually
   forward all control messages they receive.  Each control message is
   only generated once in snapct and will not be re-sent.  The pipeline
   will be locked on flushing that control message until all tiles
   forward it on. If a control message is dropped, the pipeline will
   deadlock.  Note that a tile can choose to hold onto a control message
   and forward it later after performing some asynchronous routine.  */

#define FD_SNAPSHOT_STATE_IDLE                 (0UL) /* Performing no work and should receive no data frags */
#define FD_SNAPSHOT_STATE_PROCESSING           (1UL) /* Performing usual work, no errors / EoF condition encountered */
#define FD_SNAPSHOT_STATE_FINISHING            (2UL) /* Tile has observed EoF, expects no additional data frags */
#define FD_SNAPSHOT_STATE_ERROR                (3UL) /* Some error occurred, will wait for a FAIL command to reset */
#define FD_SNAPSHOT_STATE_SHUTDOWN             (4UL) /* All work finished, tile can perform final cleanup and exit */

#define FD_SNAPSHOT_MSG_DATA                   (0UL) /* Fragment represents some snapshot data */
#define FD_SNAPSHOT_MSG_META                   (1UL) /* Fragment represents a fd_ssctrl_meta_t message */

#define FD_SNAPSHOT_MSG_CTRL_INIT_FULL         (2UL) /* Pipeline should start processing a full snapshot */
#define FD_SNAPSHOT_MSG_CTRL_INIT_INCR         (3UL) /* Pipeline should start processing an incremental snapshot */
#define FD_SNAPSHOT_MSG_CTRL_FAIL              (4UL) /* Current snapshot failed, undo work and reset to idle state */
#define FD_SNAPSHOT_MSG_CTRL_NEXT              (5UL) /* Current snapshot succeeded, commit work, go idle, and expect another snapshot */
#define FD_SNAPSHOT_MSG_CTRL_DONE              (6UL) /* Current snapshot succeeded, commit work, go idle, and expect shutdown */
#define FD_SNAPSHOT_MSG_CTRL_SHUTDOWN          (7UL) /* No work left to do, perform final cleanup and shut down */
#define FD_SNAPSHOT_MSG_CTRL_ERROR             (8UL) /* Some tile encountered an error with the current stream */

/* snapla -> snapls */
/* snaplh -> snaplv */
#define FD_SNAPSHOT_HASH_MSG_RESULT_ADD        (9UL) /* Hash result sent from snapla (snaplh) to snapls (snaplv) */

/* snapin -> snapls */
/* snapin -> snapwm -> snaplv */
#define FD_SNAPSHOT_HASH_MSG_EXPECTED         (10UL) /* Hash result sent from snapin to snapls or from snapin to snapwm to snaplv */

/* snapin -> snapls */
#define FD_SNAPSHOT_HASH_MSG_SUB              (11UL) /* Duplicate account sent from snapin to snapls, includes account header and data */
#define FD_SNAPSHOT_HASH_MSG_SUB_HDR          (12UL) /* Duplicate account sent from snapin to snapls, only the account header, no data */
#define FD_SNAPSHOT_HASH_MSG_SUB_DATA         (13UL) /* Duplicate account sent from snapin to snapls, only the account data, no header */
/* snapwm -> snaplv */
#define FD_SNAPSHOT_HASH_MSG_RESULT_SUB       (14UL) /* Duplicate partial hash result sent from snapwm to snaplv (to subtract) */
/* snapwm -> snaplv -> snaplh */
#define FD_SNAPSHOT_HASH_MSG_SUB_META_BATCH   (15UL) /* Duplicate account(s) meta batch sent from snapwm to snaplv */



/* Sent by snapct to tell snapld whether to load a local file or
   download from a particular external peer. */
typedef struct fd_ssctrl_init {
  int           file;
  int           zstd;
  ulong         slot; /* slot advertised by the snapshot peer */
  fd_ip4_port_t addr;
  char          hostname[ 256UL ];
  int           is_https;
} fd_ssctrl_init_t;

/* Sent by snapld to tell snapct metadata about a downloaded snapshot. */
typedef struct fd_ssctrl_meta {
  ulong total_sz;
  char  name[ PATH_MAX ];
} fd_ssctrl_meta_t;

struct fd_snapshot_account_hdr {
  uchar   pubkey[ FD_PUBKEY_FOOTPRINT ];
  uchar   owner[ FD_PUBKEY_FOOTPRINT ];
  ulong   lamports;
  uchar   executable;
  ulong   data_len;
};
typedef struct fd_snapshot_account_hdr fd_snapshot_account_hdr_t;

/* fd_snapshot_account_hdr_init initializes a fd_snapshot_account_hdr_t struct
   with the appropriate account metadata fields. */
static inline void
fd_snapshot_account_hdr_init( fd_snapshot_account_hdr_t * account,
                           uchar const                    pubkey[ FD_PUBKEY_FOOTPRINT ],
                           uchar const                    owner[ FD_PUBKEY_FOOTPRINT ],
                           ulong                          lamports,
                           uchar                          executable,
                           ulong                          data_len ) {
  fd_memcpy( account->pubkey, pubkey, FD_PUBKEY_FOOTPRINT );
  fd_memcpy( account->owner,  owner,  FD_PUBKEY_FOOTPRINT );
  account->lamports   = lamports;
  account->executable = executable;
  account->data_len   = data_len;
}

/* fd_snapshot_full_account is the contents of the
   SNAPSHOT_HASH_MSG_SUB message.  It contains a fd_snapshot_account_hdr_t
   header and the corresponding account data in a single message.

   For simplicity and conformance to burst limitations in snapin, the
   entire duplicate account is sent in one message (one frag).  Consider
   caching the lthash of the duplicate account so we do not have to
   send the entire account over. */
struct fd_snapshot_full_account {
  fd_snapshot_account_hdr_t hdr;
  uchar                     data[ FD_RUNTIME_ACC_SZ_MAX ];
};
typedef struct fd_snapshot_full_account fd_snapshot_full_account_t;

#define FD_SNAPSHOT_MAX_SNAPLA_TILES (8UL)
#define FD_SNAPSHOT_MAX_SNAPLH_TILES (8UL)

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssctrl_h */
