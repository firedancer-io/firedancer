#ifndef HEADER_fd_src_app_frank_fd_frank_h
#define HEADER_fd_src_app_frank_fd_frank_h

/* FD_HAS_FRANK indicates whether or not the build target supports the
   fd_frank application. */

#define FD_HAS_FRANK FD_HAS_HOSTED && FD_HAS_ALLOCA && FD_HAS_X86

#include "../../disco/fd_disco.h"

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

