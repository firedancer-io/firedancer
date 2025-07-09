#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/types/fd_types_custom.h"

struct fd_snapshot_archive_entry {
  char      filename[ PATH_MAX ];
  ulong     slot;
  fd_hash_t hash;
};

typedef struct fd_snapshot_archive_entry fd_snapshot_archive_entry_t;

struct fd_incremental_snapshot_archive_entry {
  ulong                       base_slot;
  fd_snapshot_archive_entry_t inner;
};

typedef struct fd_incremental_snapshot_archive_entry fd_incremental_snapshot_archive_entry_t;

FD_PROTOTYPES_BEGIN

int
fd_snapshot_archive_parse_full_snapshot_file( char const *                  snapshot_archive_path,
                                              char const *                  snapshot_filename,
                                              fd_snapshot_archive_entry_t * archive_entry );

int
fd_snapshot_archive_parse_incremental_snapshot_file( char const *                              snapshot_archive_path,
                                                     char const *                              snapshot_filename,
                                                     fd_incremental_snapshot_archive_entry_t * archive_entry );

int
fd_snapshot_archive_get_latest_full_snapshot( char const *                  snapshot_archive_path,
                                              fd_snapshot_archive_entry_t * full_snapshot_entry );

int
fd_snapshot_archive_get_latest_incremental_snapshot( char const *                              snapshot_archive_path,
                                                     fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_archive_h */
