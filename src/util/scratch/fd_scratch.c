#include "fd_scratch.h"

#if FD_DCHECK_STYLE>0
FD_TL int     fd_scratch_in_prepare;         /* 0    on thread start */
#endif

FD_TL ulong   fd_scratch_private_start;      /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_free;       /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_stop;       /* 0UL  on thread start */

FD_TL ulong * fd_scratch_private_frame;      /* NULL on thread start */
FD_TL ulong   fd_scratch_private_frame_cnt;  /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_frame_max;  /* 0UL  on thread start */

#if FD_HAS_ALLOCA
FD_TL ulong fd_alloca_check_private_sz;
#endif
