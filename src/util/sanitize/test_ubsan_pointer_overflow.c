#include "../fd_util_base.h"

/* test_ubsan_pointer_overflow overflows a pointer on purpose.  It is
   built only in UBSan builds and is not an automatic unit test: CI runs
   it and requires UBSan's pointer-overflow report, which shows that the
   build's real flags still have the check enabled. */

int
main( void ) {
  ulong volatile addr = ULONG_MAX;
  uchar *        ptr  = (uchar *)addr;
  ptr++;
  FD_COMPILER_UNPREDICTABLE( ptr );
  return 0;
}
