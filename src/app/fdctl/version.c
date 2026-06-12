#include "../../util/fd_util.h"
#include "version.h"

/* Legacy fdctl-compatible version symbols */
ulong const fdctl_major_version = FDCTL_MAJOR_VERSION;
ulong const fdctl_minor_version = FDCTL_MINOR_VERSION;
ulong const fdctl_patch_version = FDCTL_PATCH_VERSION;
uint        fdctl_commit_ref; /* initialized at boot */

/* fd_version */
ulong const fd_major_version = FDCTL_MAJOR_VERSION;
ulong const fd_minor_version = FDCTL_MINOR_VERSION;
ulong const fd_patch_version = FDCTL_PATCH_VERSION;

void
fd_version_private_boot( int *    pargc,
                         char *** pargv ) {
  (void)pargc; (void)pargv;
  fd_version_cstr = FDCTL_VERSION_CSTR;
  fd_version_private_commit_ref_init();
  fdctl_commit_ref = fd_commit_ref_u32;
}

__attribute__((constructor))
static void
fd_version_constructor( void ) {
  /* in case this library is used directly from Rust apps which do not
     call fd_boot */
  fd_version_private_boot( NULL, NULL );
}
