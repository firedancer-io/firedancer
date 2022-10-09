#ifndef HEADER_fd_src_app_frank_fd_frank_h
#define HEADER_fd_src_app_frank_fd_frank_h

/* FD_HAS_FRANK indicates whether or not the build target supports the
   fd_frank application. */

#define FD_HAS_FRANK FD_HAS_HOSTED && FD_HAS_ALLOCA && FD_HAS_X86

#include "../../disco/fd_disco.h"
#include "../../ballet/fd_ballet.h" /* FIXME: CONSIDER HAVING THIS IN DISCO_BASE */

/* FD_FRANK_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     ERRSV_CNT is frank speccific and the number of times a transaction
     was dropped by a verify tile due to failing signature verification. */

#define FD_FRANK_CNC_DIAG_IN_BACKP  FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_FRANK_CNC_DIAG_BACKP_CNT FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_FRANK_CNC_DIAG_ERRSV_CNT (2UL)                 /* updated by verify tile, ideally never */

FD_PROTOTYPES_BEGIN

/* fd_frank_{verify,dedup,pack}_task is a fd_tile_task_t compatible
   function whose task is to run a {verify,dedup,pack} tile.  argc is
   ignored, argv[0] points to a cstr with the tile name (for a verify,
   this is also used to find the specific verify configuration in the
   frank instance's configuration), argv[1] points to a cstr with the
   gaddr of the pod containing the frank instance's configuration and
   argv[2] points to a cstr with the path to the frank instance's
   configuration.  The lifetime of these cstr should be longer than the
   tile execution.  The argv array used to pass these cstr will not be
   used after the tile has successfully booted.  Aborts the thread group
   on error.  Returns 0 on success and non-zero on failure (logs
   details, given abortive behavior, only reason for a failure return is
   build target is without FD_HAS_FRANK). */

int
fd_frank_verify_task( int     argc,
                      char ** argv );

int
fd_frank_dedup_task( int     argc,
                     char ** argv );

int
fd_frank_pack_task( int     argc,
                    char ** argv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_frank_fd_frank_h */

