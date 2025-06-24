#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_messages_internal_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_messages_internal_h

/* The message contains a portion of the snapshot byte stream. */
#define FD_SNAPSHOT_MSG_DATA           (0UL)

/* The current snapshot byte stream is completed and there is no
   incoming snapshot byte stream. The snapshot is fully loaded and the
   upstream snapshot tiles have shutdown. */
#define FD_SNAPSHOT_MSG_CTRL_FINI      (1UL)

/* The full snapshot byte stream is completed and the incremental
   snapshot byte stream is next.  The snapshot tiles prepare to load the
   incremental snapshot. */
#define FD_SNAPSHOT_MSG_CTRL_FULL_DONE (2UL)

/* The current snapshot stream is being restarted due to insufficient
   download speed, malformed snapshot, etc.  The snapshot tiles prepare
   to re-load the current snapshot. */
#define FD_SNAPSHOT_MSG_CTRL_RETRY     (3UL)

/* The snapshot stream is reset to the full snapshot stream due to a
   fatal, recoverable error in the snapshot loading process.  The
   snapshot tiles prepare to start loading a new full snapshot. */
#define FD_SNAPSHOT_MSG_CTRL_ABANDON   (4UL)

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_messages_internal_h */
