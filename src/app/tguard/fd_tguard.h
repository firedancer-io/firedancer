#ifndef HEADER_fd_src_app_tguard_fd_tguard_h
#define HEADER_fd_src_app_tguard_fd_tguard_h

/* FD_HAS_TGUARD indicates whether or not the build target supports the
   fd_tguard application. */

#define FD_HAS_TGUARD FD_HAS_HOSTED && FD_HAS_ALLOCA && FD_HAS_X86

#include "../../disco/fd_disco.h"
#include "../../ballet/fd_ballet.h" /* FIXME: CONSIDER HAVING THIS IN DISCO_BASE */
#include "fd_tguard_cfg.h"
/* ensuing most likely need not to be modified, so placed here 
   instead in fd_tguard_cfg.h */
#define FD_TGUARD_SHREDSTORE_SLOT_CNT ((1UL<<FD_TGUARD_SHREDSTORE_LG_SLOT_CNT))
#define FD_TGUARD_ULONG_LG_SIZ (6UL) /* 64-bytes */

/* FD_TGUARD_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     {HA,SV}_FILT_{CNT,SZ} is tguard specific and the number of times a
     transaction was dropped by a verify tile due to failing signature
     verification. */

#define FD_TGUARD_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_TGUARD_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_TGUARD_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_TGUARD_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_TGUARD_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_TGUARD_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

#define FD_TGUARD_ULONG_GET_BIT(x, a)  ((x &  (   1UL << a  )))
#define FD_TGUARD_ULONG_SET_BIT(x, a)  ( x |= (   1UL << a  ) )
#define FD_TGUARD_ULONG_CLR_BIT(x, a)  ( x &= ( ~(1UL << a) ) )

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_tguard_get_storeidx( ulong slot_idx, ulong shred_idx, ulong shred_is_code) {
  return  ((slot_idx       &  (FD_TGUARD_SHREDSTORE_SLOT_CNT-1UL)) << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT-FD_TGUARD_SHREDSTORE_LG_SLOT_CNT    ))      | 
          ((shred_is_code  &                       1UL )           << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT-FD_TGUARD_SHREDSTORE_LG_SLOT_CNT-1UL))      |
          ( shred_idx      & ((1UL                                 << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT-FD_TGUARD_SHREDSTORE_LG_SLOT_CNT-1UL))-1UL)); 
}

FD_FN_CONST static inline ulong
fd_tguard_get_storeslt( ulong store_idx) {
   return (store_idx >> (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT - FD_TGUARD_SHREDSTORE_LG_SLOT_CNT))
          & ((1UL << FD_TGUARD_SHREDSTORE_LG_SLOT_CNT) - 1UL);
}

FD_FN_CONST static inline ulong
fd_tguard_get_storesltcod( ulong store_idx) {
   return (store_idx >> (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT - FD_TGUARD_SHREDSTORE_LG_SLOT_CNT - 1UL))
          & ((1UL << (FD_TGUARD_SHREDSTORE_LG_SLOT_CNT + 1UL)) - 1UL);
}

FD_FN_CONST static inline ulong
fd_tguard_get_vld_aidx( ulong store_idx) {
   return (store_idx >> FD_TGUARD_ULONG_LG_SIZ)
          & ((1UL << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT - FD_TGUARD_ULONG_LG_SIZ)) - 1UL);
}

FD_FN_CONST static inline ulong
fd_tguard_get_vld_bidx( ulong store_idx) {
   return store_idx
          & ((1UL << FD_TGUARD_ULONG_LG_SIZ) - 1UL);
}

FD_FN_CONST static inline ulong
fd_tguard_get_store_slt_lidx( ulong store_idx) {
   return store_idx
          & (~((1UL << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT - FD_TGUARD_SHREDSTORE_LG_SLOT_CNT)) - 1UL));
}

FD_FN_CONST static inline ulong
fd_tguard_get_store_slt_ridx( ulong store_idx) {
   return store_idx
          | ((1UL << (FD_TGUARD_SHREDSTORE_LG_ENTRY_CNT - FD_TGUARD_SHREDSTORE_LG_SLOT_CNT)) - 1UL);
}

int
fd_tguard_tqos_task( int     argc,
                    char ** argv );

int
fd_tguard_tmon_task( int     argc,
                    char ** argv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_tguard_fd_tguard_h */

