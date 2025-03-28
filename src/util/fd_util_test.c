#include "fd_util_test.h"

#if defined(__linux__)
#include <linux/prctl.h> /* PR_SET_DUMPABLE */
#include <sys/prctl.h> /* prctl */
#endif /* defined(__linux__) */

void
fd_test_suppress_coredump( void ) {
#if defined(__linux__)
  (void)prctl( PR_SET_DUMPABLE, 0 );
#endif
}
