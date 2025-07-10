#include "fd_ssarchive.h"

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
