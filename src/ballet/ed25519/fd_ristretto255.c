#include "fd_ristretto255_ge.h"

void const *
fd_ristretto255_validate_point( void const * point ) {
  fd_ed25519_ge_p3_t A[1];
  int ok = !!fd_ristretto255_ge_frombytes_vartime( A, point );
  return ok ? point : NULL;
}
