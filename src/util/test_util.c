#include "fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_INFO(( "fd_major_version = %lu", fd_major_version ));
  FD_LOG_INFO(( "fd_minor_version = %lu", fd_minor_version ));
  FD_LOG_INFO(( "fd_patch_version = %lu", fd_patch_version ));
  FD_LOG_INFO(( "fd_version_cstr = %s", fd_version_cstr ));
  FD_LOG_INFO(( "fd_commit_ref_cstr = %s", fd_commit_ref_cstr ));
  FD_LOG_INFO(( "fd_commit_ref_u32 = 0x%08x", fd_commit_ref_u32 ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

