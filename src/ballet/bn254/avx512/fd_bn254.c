/* avx512/fd_bn254.c — AVX-512 IFMA bn254 implementation.

   For now: delegates to the ref implementation for all operations.
   The AVX-512 pairing implementation is available but needs further
   debugging before it can replace the ref path in the syscall.

   The batched IFMA field arithmetic primitives (fd_bn254_fp52_*.h)
   are verified correct by test_bn254_avx512.  The integration into
   the full pairing pipeline (miller loop + final exp) requires
   verifying that the complex agent-generated pairing/fp12 code
   matches the ref implementation exactly. */

#include "../ref/fd_bn254.c"
