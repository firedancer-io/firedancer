#ifndef HEADER_fd_src_discof_restore_utils_fd_ssarchive_h
#define HEADER_fd_src_discof_restore_utils_fd_ssarchive_h

#include "../../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssarchive_h */
