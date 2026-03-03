#ifndef HEADER_fd_src_discof_accdb_fd_accdb_line_ctl_h
#define HEADER_fd_src_discof_accdb_fd_accdb_line_ctl_h

/* fd_accdb_line_ctl.h provides the ctl field encoding for accdb cache
   lines.  This header is shared between the accdb tile
   (fd_accdb_tile_private.h) and specread clients (fd_accdb_specread.h).

   Layout:
     bits [32,64)  version   (same as fd_vinyl_line_ctl)
     bit  25       EVICTING
     bit  24       CHANCE
     bits [0,24)   ref + 1   (combined client + specread ref count)

   Specread pin:   FETCH_AND_ADD(&ctl, 1UL), check old & EVICTING
   Specread unpin: FETCH_AND_SUB(&ctl, 1UL)
   CHANCE set:     FETCH_AND_OR(&ctl, FD_ACCDB_LINE_CTL_CHANCE)
   CHANCE clear:   FETCH_AND_AND(&ctl, ~FD_ACCDB_LINE_CTL_CHANCE)
   EVICTING set:   CAS or FETCH_AND_OR on ctl
   Version bump:   CAS loop (preserves in-flight specread refs) */

#include "../../util/fd_util_base.h"

#define FD_ACCDB_LINE_CTL_CHANCE   (1UL << 24)
#define FD_ACCDB_LINE_CTL_EVICTING (1UL << 25)

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_accdb_line_ctl( ulong ver, long ref ) {
  return (ver << 32) | ((ulong)(ref + 1L));
}

FD_FN_CONST static inline ulong fd_accdb_line_ctl_ver( ulong ctl ) { return ctl >> 32; }
FD_FN_CONST static inline long  fd_accdb_line_ctl_ref( ulong ctl ) { return ((long)(ctl & ((1UL<<24)-1UL))) - 1L; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_line_ctl_h */
