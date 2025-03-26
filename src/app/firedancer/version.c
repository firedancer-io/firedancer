#include "../../util/fd_util.h"
#include "version.h"

#ifndef FIREDANCER_PATCH_VERSION
#define FIREDANCER_PATCH_VERSION 9999
#endif
#ifndef FIREDANCER_COMMIT_REF_CSTR
#define FIREDANCER_COMMIT_REF_CSTR "0000000000000000000000000000000000000000"
#endif
#ifndef FIREDANCER_COMMIT_REF_U32
#define FIREDANCER_COMMIT_REF_U32 0x0
#endif

ulong const firedancer_major_version     = FIREDANCER_MAJOR_VERSION;
ulong const firedancer_minor_version     = FIREDANCER_MINOR_VERSION;
ulong const firedancer_patch_version     = FIREDANCER_PATCH_VERSION;
uint  const firedancer_commit_ref        = FIREDANCER_COMMIT_REF_U32;
char  const firedancer_commit_ref_string[] = FIREDANCER_COMMIT_REF_CSTR;
char  const firedancer_version_string[]  = FD_EXPAND_THEN_STRINGIFY(FIREDANCER_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FIREDANCER_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FIREDANCER_PATCH_VERSION);

// Some shared code assumes the fdctl version numbers, just replace them
char  const fdctl_commit_ref_string[] = FIREDANCER_COMMIT_REF_CSTR;
char  const fdctl_version_string[]  = FD_EXPAND_THEN_STRINGIFY(FIREDANCER_MAJOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FIREDANCER_MINOR_VERSION) "." FD_EXPAND_THEN_STRINGIFY(FIREDANCER_PATCH_VERSION);
