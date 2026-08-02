#ifndef HEADER_fd_src_discof_backup_fd_snapmk_tile_h
#define HEADER_fd_src_discof_backup_fd_snapmk_tile_h

/* fd_snapmk_tile.h specifies the snapmk tile ABI.
   The snapmk tile is the IPC entrypoint for snapshot production. */

#include "fd_backup.h"
#include "../../tango/fd_tango_base.h"

/* snapmk_out ABI

   snapmk_out is a reliable tango link with dcache alloc policy.
   mcache descriptor fields as follows:
   - seq: sequence number
   - sig: payload type (FD_SNAPMK_MSG_*)
   - chunk: compressed payload pointer (fd_chunk_to_laddr wksp-relative)
   - sz: payload size
   - tspub: compressed tickcount event timestamp
   Other fields are reserved for future use.

   Consumers can replay found/created/deleted messages to reconstruct a
   live view of all available snapshots on the file system.*/

/* FD_SNAPMK_MSG_* give message types */

#define FD_SNAPMK_MSG_FOUND   1 /* fd_snapmk_msg_found_t */
#define FD_SNAPMK_MSG_CREATED 2 /* fd_snapmk_msg_created_t */
#define FD_SNAPMK_MSG_DELETED 3 /* fd_snapmk_msg_deleted_t */
#define FD_SNAPMK_MSG_STARTED 4 /* fd_snapmk_msg_started_t */
#define FD_SNAPMK_MSG_FAILED  5 /* fd_snapmk_msg_failed_t */

/* fd_snapmk_msg_found_t signals that a pre-existing snapshot was found
   on the file system.  That snapshot comes from a previous run or was
   just downloaded by the snapshot loading pipeline.

   A burst of these messages is also created after startup (once the
   snapshot loading pipeline finishes). */

struct fd_snapmk_msg_found {
  ulong slot;      /* snapshot slot */
  ulong base_slot; /* ULONG_MAX if full snapshot */
  ulong sz;        /* snapshot file size */
  uint  pool_idx;  /* FD_SNAP_FD( pool_idx ) -> snap file descriptor */
  uint  reserved;
  char  name[ FD_SNAP_NAME_MAX ];
  long  fs_timestamp; /* unix nanosecond timestamp from file (LONG_MAX if unknown) */
};

typedef struct fd_snapmk_msg_found fd_snapmk_msg_found_t;

/* fd_snapmk_msg_created_t signals that a new snapshot was just produced
   and is available on the file system. */

struct fd_snapmk_msg_created {
  ulong slot;      /* snapshot slot */
  ulong base_slot; /* ULONG_MAX if full snapshot */
  ulong sz;        /* snapshot file size */
  uint  pool_idx;  /* FD_SNAP_FD( pool_idx ) -> snap file descriptor */
  uint  reserved;
  char  name[ FD_SNAP_NAME_MAX ];
};

typedef struct fd_snapmk_msg_created fd_snapmk_msg_created_t;

/* fd_snapmk_msg_deleted_t signals that a snapshot is about to be
   deleted. */

struct fd_snapmk_msg_deleted {
  ulong slot;
  ulong base_slot; /* ULONG_MAX if full snapshot */
  uint  pool_idx; /* FD_SNAP_FD( pool_idx ) -> snap file descriptor */
  uint  reserved1;
  char  name[ FD_SNAP_NAME_MAX ];
};

typedef struct fd_snapmk_msg_deleted fd_snapmk_msg_deleted_t;

/* fd_snapmk_msg_started_t signals that the snapshot production pipeline
   has started.  Will eventually be followed by a created or failed msg. */

struct fd_snapmk_msg_started {
  ulong slot;
  ulong base_slot; /* ULONG_MAX if full snapshot */
  uint  pool_idx; /* FD_SNAP_FD( pool_idx ) -> snap file descriptor */
};

typedef struct fd_snapmk_msg_started fd_snapmk_msg_started_t;

/* fd_snapmk_msg_failed_t signals that snapshot production failed.
   Currently, there is only one failure reason: too many accounts
   changed since the full snapshot to fit in the incremental snap. */

struct fd_snapmk_msg_failed {
  ulong slot;
  ulong base_slot; /* ULONG_MAX if full snapshot */
  uint  reserved;
};

typedef struct fd_snapmk_msg_failed fd_snapmk_msg_failed_t;

/* fd_snapmk_msg_t is the data payload behind the fd_frag_meta_t::chunk
   compressed offset. */

union fd_snapmk_msg {
  fd_snapmk_msg_found_t   found;
  fd_snapmk_msg_created_t created;
  fd_snapmk_msg_deleted_t deleted;
  fd_snapmk_msg_started_t started;
  fd_snapmk_msg_failed_t  failed;
};

typedef union fd_snapmk_msg fd_snapmk_msg_t;

#endif /* HEADER_fd_src_discof_backup_fd_snapmk_tile_h */
