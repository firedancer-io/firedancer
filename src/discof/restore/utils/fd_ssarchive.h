#ifndef HEADER_fd_src_discof_restore_utils_fd_ssarchive_h
#define HEADER_fd_src_discof_restore_utils_fd_ssarchive_h

#include "../../../util/fd_util_base.h"
#include "../../../flamenco/types/fd_types_custom.h"

FD_PROTOTYPES_BEGIN

/* Parses a snapshot filename like

    incremental-snapshot-344185432-344209085-45eJ5C91fEenPRFc8NiqaDXMCHcPFwRUTMH3k1zY6a1B.tar.zst
    snapshot-344185432-BSP9ztdFEjwvkBo2LhHA47g9Q3PDwja9x5fj7taFRKH5.tar.zst

   into components.  Returns one of FD_SSARCHIVE_PARSE_*.  On success
   the snapshot will be either a FULL or INCREMENTAL parse result.  If
   incremental, the incremental slot will be set to ULONG_MAX, otherwise
   it is set to the incremental slot number.  On success, the full slot
   is always set and the hash is set if get_hash is true.  The hash is
   the base58 decoded hash. */

int
fd_ssarchive_parse_filename( char *  _name,
                             ulong * full_slot,
                             ulong * incremental_slot,
                             uchar   hash[ static FD_HASH_FOOTPRINT ] );

/* Given a directory on the filesystem, determine the
   (full, incremental) slot pair, and the snapshot paths for them which
   gives the highest incremental slot.  The incremental slot is set to
   ULONG_MAX if the highest pair is just a full snapshot alone, or if
   incremental_snapshot is 0.

   Returns -1 on failure, and 0 on success. */

int
fd_ssarchive_latest_pair( char const * directory,
                          int          incremental_snapshot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ] );

/* Given a directory on the file system, remove old snapshots by slot
   age until the number of full snapshots matches the
   max_full_snapshots_to_keep and the number of incremental snapshots
   matches the max_incremental_snapshots_to_keep parameter. */
void
fd_ssarchive_remove_old_snapshots( char const * directory,
                                   uint         max_full_snapshots_to_keep,
                                   uint         max_incremental_snapshots_to_keep );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssarchive_h */
