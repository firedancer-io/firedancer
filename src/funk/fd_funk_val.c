#include "fd_funk.h"

#if FD_HAS_HOSTED && FD_HAS_X86

int
fd_funk_val_verify( fd_funk_t * funk ) {
  (void)funk; FD_COMPILER_MFENCE();
  return FD_FUNK_SUCCESS;
}

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
