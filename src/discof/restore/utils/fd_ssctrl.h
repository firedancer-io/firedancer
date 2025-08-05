#ifndef HEADER_fd_src_discof_restore_utils_fd_ssctrl_h
#define HEADER_fd_src_discof_restore_utils_fd_ssctrl_h

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

/* The HIGHEST_MANIFEST_SLOT message is an informational control message
   that is forwarded from the snaprd tile to the snapin tile, which
   forwards the message to the snap_out link.  The HIGHEST_MANIFEST_SLOT
   message contains the highest manifest slot so far.  It is typically
   the incremental snapshot slot but can be the full snapshot slot if
   incremental snapshots are disabled.  It is guaranteed to be
   monotonically increasing and is forwarded regardless of any snapshot
   loading error / retry. */
#define FD_SNAPSHOT_MSG_HIGHEST_MANIFEST_SLOT  (1UL) /* Fragment contains the highest manifest slot so far, guaranteed to be monotonically increasing */

#define FD_SNAPSHOT_MSG_CTRL_RESET_FULL        (2UL) /* Reset to start loading a fresh full snapshot */
#define FD_SNAPSHOT_MSG_CTRL_EOF_FULL          (3UL) /* Full snapshot data is done, incremental data starting now */
#define FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL (4UL) /* Incremental data being retried, start incremental over */
#define FD_SNAPSHOT_MSG_CTRL_DONE              (5UL) /* Snapshot load is over, data is finished for this tile */
#define FD_SNAPSHOT_MSG_CTRL_SHUTDOWN          (6UL) /* All tiles have acknowledged snapshot load is done, can now shutdown */

#define FD_SNAPSHOT_MSG_CTRL_ACK               (7UL) /* Sent from tiles back to snaprd, meaning they ACK whatever control message was pending */
#define FD_SNAPSHOT_MSG_CTRL_MALFORMED         (8UL) /* Sent from tiles back to snaprd, meaning they consider the current snapshot malformed */

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssctrl_h */
