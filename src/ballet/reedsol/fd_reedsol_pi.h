#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_pi_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_pi_h
#include "../../util/fd_util_base.h"

/* This file generates what
     S. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
     Polynomial Basis With Fast Fourier Transform and Its Application to
     Reed–Solomon Erasure Codes," in IEEE Transactions on Information
     Theory, vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi:
     10.1109/TIT.2016.2608892.
   and
     Didier, Frédéric. "Efficient erasure decoding of Reed-Solomon
     codes." arXiv preprint arXiv:0901.1886 (2009).
   call Pi and 1/Pi'. For more information about Pi and Pi', see the
   implementation or the papers referenced above.

   The main set of functions this file exposes is

     void fd_reedsol_gen_pi_{N}( uchar const * is_erased, uchar * output )

   for N in {16, 32, 64, 128, 256}. Since Pi is only needed for elements
   that are not erased, Pi' is only needed for elements that are erased,
   and it is computationally beneficial to compute them at the same
   time, this function computes them both.

   is_erased and output must point to the first element of arrays
   indexed [0, N).  They must be aligned to 32 bytes.

   Upon return, output[i] stores Pi(i) if is_erased[i]==0 and 1/Pi'(i)
   if is_erased[i]==1.  It's undefined behavior for is_erased to contain
   something other than 0 or 1.

   Pi and Pi' are both elements of GF(2^8) stored in their normal byte
   representation. */
void fd_reedsol_gen_pi_16 ( uchar const * is_erased, uchar * output );
void fd_reedsol_gen_pi_32 ( uchar const * is_erased, uchar * output );
void fd_reedsol_gen_pi_64 ( uchar const * is_erased, uchar * output );
void fd_reedsol_gen_pi_128( uchar const * is_erased, uchar * output );
void fd_reedsol_gen_pi_256( uchar const * is_erased, uchar * output );

/* The following are the pre-computed values for common cases.
   They're exposed in this header so that the values to multiply are
   known at compile time to eliminate loads on the critical path. */
/* TODO: Decide on pre-computed cases and add them */


#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_pi_h */
