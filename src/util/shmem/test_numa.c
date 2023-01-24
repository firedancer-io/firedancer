#define _GNU_SOURCE
#include "../fd_util.h"

/* Include OS-specific tests */

#if FD_HAS_HOSTED

#define SOURCE_fd_src_util_shmem_test_numa
#ifdef __linux__
#include "test_numa_linux.c"
#endif

/* Include generic tests */
#include <errno.h>

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( !fd_numa_available() ) ) {
    FD_LOG_WARNING(( "fd_numa_available()==0, skipping test" ));
    fd_halt();
    return 0;
  }

  int node_cnt    = fd_shmem_numa_cnt_private();
  int cpu_cnt     = fd_shmem_cpu_cnt_private();
  int cpu_max_cnt = fd_numa_cpu_max_cnt();

  FD_LOG_NOTICE(( "fd_shmem_numa_cnt_private()    = %i", node_cnt    ));
  FD_LOG_NOTICE(( "fd_shmem_cpu_cnt_private()     = %i", cpu_cnt     ));
  FD_LOG_NOTICE(( "fd_numa_cpu_max_cnt() = %i", cpu_max_cnt ));

  FD_TEST( node_cnt   > 0        );
  FD_TEST( cpu_cnt    >=node_cnt );
  FD_TEST( cpu_max_cnt>=cpu_cnt  );

  FD_TEST( fd_numa_node_of_cpu( -1            )==-ENOENT );
  FD_TEST( fd_numa_node_of_cpu( cpu_max_cnt   )==-ENOENT );
  FD_TEST( fd_numa_node_of_cpu( cpu_max_cnt+1 )==-ENOENT );

  int actual_cpu_cnt = 0;
  for( int i=0; i<cpu_max_cnt; i++ ) {
    int res = fd_numa_node_of_cpu( i );
    if( FD_LIKELY( res>=0 ) ) {
      actual_cpu_cnt++;
      FD_LOG_NOTICE(( "fd_numa_node_of_cpu(%i) = %i", i, res ));
    } else {
      FD_LOG_NOTICE(( "fd_numa_node_of_cpu(%i) = (%i-%s)",
                      i, -res, strerror( -res ) ));
      if( FD_UNLIKELY( res!=-ENOENT ) ) {
        FD_LOG_ERR(( "fd_numa_node_of_cpu failed for CPU %i (%i-%s)",
                     i, -res, strerror( -res ) ));
      }
    }
  }

  FD_TEST( cpu_cnt==actual_cpu_cnt );

# ifdef __linux__
  test_numa_linux();
# endif

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else /* FD_HAS_HOSTED */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED acapabilities" ));
  fd_halt();
  return 0;
}

#endif
