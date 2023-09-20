#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"
#include "../ballet/txn/fd_txn.h"

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU. */
#define FD_TPU_MTU (1232UL)

/* FD_TPU_DCACHE_MTU is the max size of a dcache entry */
#define FD_TPU_DCACHE_MTU (FD_TPU_MTU + FD_TXN_MAX_SZ + 2UL)

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))

/* FD_APP_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     {HA,SV}_FILT_{CNT,SZ} is app specific and the number of times a
     transaction was dropped by a verify tile due to failing signature
     verification. */

#define FD_APP_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_APP_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_APP_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_APP_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_APP_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_APP_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

#define FD_APP_CNC_DIAG_PID         (128UL)

//FD_PROTOTYPES_BEGIN

/* This is currently just a stub in anticipation of future common tile
   functionality */

//FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_base_h */

