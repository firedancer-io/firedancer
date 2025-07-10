#ifndef HEADER_fd_src_discof_restore_utils_fd_ssarchive_h
#define HEADER_fd_src_discof_restore_utils_fd_ssarchive_h

#include "../../../util/fd_util_base.h"

#define FD_SSARCHIVE_PARSE_INVALID     (-1)
#define FD_SSARCHIVE_PARSE_FULL        ( 0)
#define FD_SSARCHIVE_PARSE_INCREMENTAL ( 1)

FD_PROTOTYPES_BEGIN

/* Parses a snapshot filename like

    incremental-snapshot-344185432-344209085-45eJ5C91fEenPRFc8NiqaDXMCHcPFwRUTMH3k1zY6a1B.tar.zst
    snapshot-344185432-BSP9ztdFEjwvkBo2LhHA47g9Q3PDwja9x5fj7taFRKH5.tar.zst

   into components.  Returns one of FD_SSARCHIVE_PARSE_*.  On success
   the snapshot will be either a FULL or INCREMENTAL parse result.  If
   incremental, the incremental slot will be set to ULONG_MAX, otherwise
   it is set to the incremental slot number.  On success, the full slot
   and the snapshot hash are always set.  The hash will be the base58
   decoded hash. */

int
fd_ssarchive_parse( char const * filename,
                    ulong *      full_slot,
                    ulong *      incremental_slot,
                    uchar        hash[ static 32UL ] );

/* Given a directory on the filesystem, determine the
   (full, incremental) slot pair, and the snapshot paths for them which
   gives the highest incremental slot.  The incremental slot is set to
   ULONG_MAX if the highest pair is just a full snapshot alone.

   Returns -1 on failure, and 0 on success. */

int
fd_ssarchive_latest_pair( char const * directory,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssarchive_h */