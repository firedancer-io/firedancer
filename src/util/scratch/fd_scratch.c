#include "fd_scratch.h"

FD_TLS int     fd_scratch_in_prepare;         /* 0    on thread start */

FD_TLS ulong   fd_scratch_private_start;      /* 0UL  on thread start */
FD_TLS ulong   fd_scratch_private_free;       /* 0UL  on thread start */
FD_TLS ulong   fd_scratch_private_stop;       /* 0UL  on thread start */

FD_TLS ulong * fd_scratch_private_frame;      /* NULL on thread start */
FD_TLS ulong   fd_scratch_private_frame_cnt;  /* 0UL  on thread start */
FD_TLS ulong   fd_scratch_private_frame_max;  /* 0UL  on thread start */

