#ifndef HEADER_fd_src_disco_diag_fd_diag_tile_h
#define HEADER_fd_src_disco_diag_fd_diag_tile_h

#define FD_DIAG_BUNDLE_STATUS_DISABLED     (0UL) /* No bundle tiles configured */
#define FD_DIAG_BUNDLE_STATUS_DISCONNECTED (1UL) /* All bundle tiles disconnected */
#define FD_DIAG_BUNDLE_STATUS_CONNECTING   (2UL) /* At least one bundle tile connecting, none connected or sleeping */
#define FD_DIAG_BUNDLE_STATUS_CONNECTED    (3UL) /* At least one bundle tile connected */
#define FD_DIAG_BUNDLE_STATUS_SLEEPING     (4UL) /* At least one bundle tile sleeping, none connected */

#define FD_DIAG_VOTE_STATUS_DISABLED    (0UL) /* Non-voting or no tower tile */
#define FD_DIAG_VOTE_STATUS_NOT_STARTED (1UL) /* Tower tile not running or no votes cast yet */
#define FD_DIAG_VOTE_STATUS_DELINQUENT  (2UL) /* Vote distance exceeds threshold or vote stalled */
#define FD_DIAG_VOTE_STATUS_VOTING      (3UL) /* Voting normally */

#define FD_DIAG_REPLAY_STATUS_DISABLED    (0UL) /* No replay tile */
#define FD_DIAG_REPLAY_STATUS_NOT_STARTED (1UL) /* Replay tile not running or slots are zero */
#define FD_DIAG_REPLAY_STATUS_BEHIND      (2UL) /* Replay lagging behind turbine or reset slot stalled */
#define FD_DIAG_REPLAY_STATUS_RUNNING     (3UL) /* Replay keeping up */

#define FD_DIAG_TURBINE_STATUS_DISABLED         (0UL) /* No shred or replay tiles */
#define FD_DIAG_TURBINE_STATUS_NOT_STARTED      (1UL) /* Tiles not all running or turbine slot is zero */
#define FD_DIAG_TURBINE_STATUS_STALLED          (2UL) /* Turbine slot not advancing */
#define FD_DIAG_TURBINE_STATUS_REPAIR_OUTPACING (3UL) /* Repair byte throughput exceeds turbine */
#define FD_DIAG_TURBINE_STATUS_RUNNING          (4UL) /* Turbine receiving normally */

#endif /* HEADER_fd_src_disco_diag_fd_diag_tile_h */
