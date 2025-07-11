#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/types/fd_types_custom.h"

/* fd_full_snapshot_archive_entry contains the full absolute path to the
   full snapshot file and components parsed from the snapshot name,
   which includes the slot and hash. */
struct fd_full_snapshot_archive_entry {
   char      full_path[ PATH_MAX ]; /* Absolute path to snapshot file on disk. */
   ulong     slot;                  /* Slot of the full snapshot */
   fd_hash_t hash;                  /* Hash of all accounts in the snapshot  */
};
typedef struct fd_full_snapshot_archive_entry fd_full_snapshot_archive_entry_t;

/* fd_incremental_snapshot_archive_entry contains the full absolute path
   to the incremental snapshot and components parsed from the snapshot
   name, which includes the base slot, slot, and hash. */
struct fd_incremental_snapshot_archive_entry {
  char      full_path[ PATH_MAX ]; /* Absolute path to snapshot file on disk. */
  ulong     base_slot;             /* Slot of the full snapshot this incremental snapshot builds off */
  ulong     slot;                  /* Slot of the incremental snapshot */
  fd_hash_t hash;                  /* Hash of all accounts in the snapshot */
};
typedef struct fd_incremental_snapshot_archive_entry fd_incremental_snapshot_archive_entry_t;

FD_PROTOTYPES_BEGIN

/* Given a snapshots archive directory, finds the most recent full
   snapshot file and populates the full_snapshot_entry accordingly.

   On success, the full_snapshot_entry is populated with the
   full absolute path of the snapshot file and its parsed components.
   Returns -1 on failure. On failure, the slot in the snapshot entry
   is set to ULONG_MAX. */
int
fd_snapshot_archive_get_latest_full_snapshot( char const *                       snapshot_archive_path,
                                              fd_full_snapshot_archive_entry_t * full_snapshot_entry );

/* Given a snapshots archive directory, finds the most recent
   incremental snapshot file and populates the
   incremental_snapshot_entry accordingly.

   On success, the incremental_snapshot_entry is populated with the
   full absolute path of the snapshot file and its parsed components.
   Returns -1 on failure. On failure, the base slot and slot in the
   snapshot entry is set to ULONG_MAX. */
int
fd_snapshot_archive_get_latest_incremental_snapshot( char const *                              snapshot_archive_path,
                                                     fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h */
