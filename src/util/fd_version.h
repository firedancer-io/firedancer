#ifndef HEADER_fd_src_util_fd_version_h
#define HEADER_fd_src_util_fd_version_h

#include "fd_util_base.h"

/* Version information provided by the build system.

   These may return incorrect values before fd_boot(). */

extern ulong const  fd_major_version;
extern ulong const  fd_minor_version;
extern ulong const  fd_patch_version;
extern char const * fd_version_cstr;
extern char const * fd_commit_ref_cstr; /* cstr */
extern uint         fd_commit_ref_u32;

FD_PROTOTYPES_BEGIN

void
fd_version_private_boot( int *    pargc,
                         char *** pargv );

void
fd_version_private_commit_ref_init( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fd_version_h */
