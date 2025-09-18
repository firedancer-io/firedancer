#include "fd_accdb_session.h"
#include <stddef.h>

/* Check for 64 byte aligned points */
FD_STATIC_ASSERT( offsetof( fd_accdb_sestab_t, magic           )== 0UL, align );
FD_STATIC_ASSERT( offsetof( fd_accdb_sestab_t, mgr_session_idx )==64UL, align );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
