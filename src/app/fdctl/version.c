#include "../../util/fd_util.h"
#include "version.h"

#ifndef FDCTL_PATCH_VERSION
#define FDCTL_PATCH_VERSION 9999
#endif
#ifndef FDCTL_COMMIT_REF_CSTR
#define FDCTL_COMMIT_REF_CSTR "0000000000000000000000000000000000000000"
#endif
#ifndef FDCTL_COMMIT_REF_U32
#define FDCTL_COMMIT_REF_U32 0x0
#endif

ulong const fdctl_major_version     = FDCTL_MAJOR_VERSION;
ulong const fdctl_minor_version     = FDCTL_MINOR_VERSION;
ulong const fdctl_patch_version     = FDCTL_PATCH_VERSION;
uint  const fdctl_commit_ref        = FDCTL_COMMIT_REF_U32;
char  const fdctl_commit_ref_string[] = FDCTL_COMMIT_REF_CSTR;
char  const fdctl_version_string[]  = FD_EXPAND_THEN_STRINGIFY(FDCTL_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FDCTL_PATCH_VERSION);
