#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h

/* Contains function declarations for the interal encoding and recovery
   functions.  */

#include "fd_reedsol.h"

/* FD_REEDSOL_ARITH_IMPL is used to select which implementation of
   Galois Field arithmetic should be used.  Supported implementations
   include:

     0 - unaccelerated
     1 - AVX accelerated
     2 - GFNI accelerated */

#ifndef FD_REEDSOL_ARITH_IMPL
#if FD_HAS_GFNI
#define FD_REEDSOL_ARITH_IMPL 2
#elif FD_HAS_AVX
#define FD_REEDSOL_ARITH_IMPL 1
#else
#define FD_REEDSOL_ARITH_IMPL 0
#endif
#endif

#if FD_REEDSOL_ARITH_IMPL==0
#include "fd_reedsol_arith_none.h"
#elif FD_REEDSOL_ARITH_IMPL==1
#include "fd_reedsol_arith_avx2.h"
#elif FD_REEDSOL_ARITH_IMPL==2
#include "fd_reedsol_arith_gfni.h"
#else
#error "Unsupported FD_REEDSOL_ARITH_IMPL"
#endif

/* FALLTHRU: Tells the compiler that falling through to the next case
   of the switch statement is intentional and not a bug.  When brutality
   is turned on, this must be used.  Clang an GCC differ on what
   annotations they accept, but this works for both. */
/* TODO: CONSIDER MOVING SOMETHING LIKE THIS TO UTIL_BASE.H? */

#define FALLTHRU __attribute__((fallthrough));

FD_PROTOTYPES_BEGIN

/* fd_reedsol_private_encode_{n} requires that data_shred_cnt <= n */

void
fd_reedsol_private_encode_16(  ulong                 shred_sz,
                               uchar const * const * data_shred,
                               ulong                 data_shred_cnt,
                               uchar       * const * parity_shred,
                               ulong                 parity_shred_cnt );

void
fd_reedsol_private_encode_32( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              ulong                 data_shred_cnt,
                              uchar       * const * parity_shred,
                              ulong                 parity_shred_cnt );

void
fd_reedsol_private_encode_64( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              ulong                 data_shred_cnt,
                              uchar       * const * parity_shred,
                              ulong                 parity_shred_cnt );

void
fd_reedsol_private_encode_128( ulong                 shred_sz,
                               uchar const * const * data_shred,
                               ulong                 data_shred_cnt,
                               uchar       * const * parity_shred,
                               ulong                 parity_shred_cnt );

#if FD_HAS_GFNI
void
fd_reedsol_private_encode_32_32( ulong                 shred_sz,
                                 uchar const * const * data_shred,
                                 uchar       * const * parity_shred,
                                 uchar       *         _scratch );
#endif

/* fd_reedsol_private_recover_var_{n}: Verifies the consistency
   of the Reed-Solomon encoded data, and recovers any missing data.
   At least data_shred_cnt of the first n shreds must be un-erased,
   which implies data_shred_cnt <= n.

   Unlike the encode operations, the math doesn't care much whether a
   shred is a data shred or parity shred for recover operations, hence
   the function only has one shred array.  The parity shreds come
   immediately after the data shreds.

   For each value of i in [0, data_shred_cnt+parity_shred_cnt), erased[
   i ] must be 0 (if shred[ i ] contains valid data) or 1 if shred[ i ]
   is an erasure (i.e. wasn't received, was corrupted, etc.).  If
   erased[ i ]==1, the contents of shred[ i ] are ignored on entry, and
   upon return, shred[ i ][ j ] will be overwritten with the correct
   data for j in [0, shred_sz).

   Note that since data_shred_cnt+parity_shred_cnt<=134, shred[ i ] and
   erased[ i ] for i>=134 are completely ignored.

   Returns one of:

   FD_REEDSOL_SUCCESS if okay

   FD_REEDSOL_ERR_CORRUPT if the shreds are not consistent with having
   come from a Reed-Solomon encoding of data_shred_cnt data shreds

   FD_REEDSOL_ERR_PARTIAL if there's not enough un-erased data to
   recover data_shred_cnt data shreds

   TODO: Add a recover_private_first_{n} variant that imposes the
   additional constraint that the first data_shred_cnt shreds must be
   un-erased, is the case when no packets have been lost.  Would be
   slightly faster. */

int
fd_reedsol_private_recover_var_16( ulong           shred_sz,
                                   uchar * const * shred,
                                   ulong           data_shred_cnt,
                                   ulong           parity_shred_cnt,
                                   uchar const *   erased );

int
fd_reedsol_private_recover_var_32( ulong           shred_sz,
                                   uchar * const * shred,
                                   ulong           data_shred_cnt,
                                   ulong           parity_shred_cnt,
                                   uchar const *   erased );

int
fd_reedsol_private_recover_var_64( ulong           shred_sz,
                                   uchar * const * shred,
                                   ulong           data_shred_cnt,
                                   ulong           parity_shred_cnt,
                                   uchar const *   erased );

int
fd_reedsol_private_recover_var_128( ulong           shred_sz,
                                    uchar * const * shred,
                                    ulong           data_shred_cnt,
                                    ulong           parity_shred_cnt,
                                    uchar const *   erased );

int
fd_reedsol_private_recover_var_256( ulong           shred_sz,
                                    uchar * const * shred,
                                    ulong           data_shred_cnt,
                                    ulong           parity_shred_cnt,
                                    uchar const *   erased );

/* This below functions generate what:

     S. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
     Polynomial Basis With Fast Fourier Transform and Its Application to
     Reed–Solomon Erasure Codes," in IEEE Transactions on Information
     Theory, vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi:
     10.1109/TIT.2016.2608892.

   and:

     Didier, Frédéric. "Efficient erasure decoding of Reed-Solomon
     codes." arXiv preprint arXiv:0901.1886 (2009).

   call Pi and 1/Pi'. For more information about Pi and Pi', see the
   implementation or the papers referenced above.

   The main set of functions this file exposes is:

     void fd_reedsol_private_gen_pi_{N}( uchar const * is_erased, uchar * output )

   for N in {16, 32, 64, 128, 256}.  Since Pi is only needed for
   elements that are not erased, Pi' is only needed for elements that
   are erased, and it is computationally beneficial to compute them at
   the same time, this function computes them both.

   is_erased and output must point to the first element of arrays
   indexed [0, N).  They must be aligned to 32 bytes.

   Upon return, output[i] stores Pi(i) if is_erased[i]==0 and 1/Pi'(i)
   if is_erased[i]==1.  It's undefined behavior for is_erased to contain
   something other than 0 or 1.

   Pi and Pi' are both elements of GF(2^8) stored in their normal byte
   representation. */

void fd_reedsol_private_gen_pi_16 ( uchar const * is_erased, uchar * output );
void fd_reedsol_private_gen_pi_32 ( uchar const * is_erased, uchar * output );
void fd_reedsol_private_gen_pi_64 ( uchar const * is_erased, uchar * output );
void fd_reedsol_private_gen_pi_128( uchar const * is_erased, uchar * output );
void fd_reedsol_private_gen_pi_256( uchar const * is_erased, uchar * output );

/* The following are the pre-computed values for common cases.
   They're exposed in this header so that the values to multiply are
   known at compile time to eliminate loads on the critical path. */

/* TODO: Decide on pre-computed cases and add them */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h */
