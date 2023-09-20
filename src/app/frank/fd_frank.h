#ifndef HEADER_fd_src_app_frank_fd_frank_h
#define HEADER_fd_src_app_frank_fd_frank_h

#include "../../disco/fd_disco.h"
#include "../../ballet/fd_ballet.h" /* FIXME: CONSIDER HAVING THIS IN DISCO_BASE */
#include "../../tango/xdp/fd_xsk.h"

/* FD_FRANK_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     {HA,SV}_FILT_{CNT,SZ} is frank specific and the number of times a
     transaction was dropped by a verify tile due to failing signature
     verification. */

#define FD_FRANK_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_FRANK_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_FRANK_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_FRANK_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_FRANK_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_FRANK_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

#define FD_FRANK_CNC_DIAG_PID         (128UL)

typedef struct {
   int           pid;
   char *        app_name;
   char *        tile_name;
   ulong         tile_idx;
   ulong         idx;
   uchar const * tile_pod;
   uchar const * in_pod;
   uchar const * out_pod;
   uchar const * extra_pod;
   fd_xsk_t    * xsk;
   fd_xsk_t    * lo_xsk;
   double        tick_per_ns;
   void        * other;
} fd_frank_args_t;

typedef struct {
   char *  name;
   char *  in_wksp;
   char *  out_wksp;
   char *  extra_wksp;
   ushort  allow_syscalls_sz;
   long *  allow_syscalls;
   ulong (*allow_fds)( fd_frank_args_t * args, ulong out_fds_sz, int * out_fds );
   void  (*init)( fd_frank_args_t * args );
   void  (*run )( fd_frank_args_t * args );
} fd_frank_task_t;

extern fd_frank_task_t frank_verify;
extern fd_frank_task_t frank_dedup;
extern fd_frank_task_t frank_quic;
extern fd_frank_task_t frank_pack;
extern fd_frank_task_t frank_forward;
extern fd_frank_task_t frank_shred;

#endif /* HEADER_fd_src_app_frank_fd_frank_h */
