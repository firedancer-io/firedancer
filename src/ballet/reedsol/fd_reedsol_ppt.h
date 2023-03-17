
/* Note: This file is auto generated. */
#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h

/* This file implements the Principal Pivot Transform for the Reed
   Solomon FFT operator as described in:
     S. -J. Lin, A. Alloum and T. Al-Naffouri, "Principal pivot
     transforms on radix-2 DFT-type matrices," 2017 IEEE International
     Symposium on Information Theory (ISIT), Aachen, Germany, 2017, pp.
     2358-2362, doi: 10.1109/ISIT.2017.8006951

   The main macro this file provides is FD_REEDSOL_GENERATE_PPT.  The
   rest of this file is auto-generated implementation details.


   When the number of data shreds we have is not a power of 2, the
   approach used in the 32-32 case doesn't apply.  I found the paper
   extending it to the general case uninterpretable.  So we use the
   principal pivot transform as an alternative with similar
   computational complexity.

   The goal of the first step of the 32-32 case is to find a polynomial
   of degree < 32 that interpolates the data shreds.  If we only have k
   data shreds, where k<32, then instead we need a polynomial P of
   degree <k that passes through the k data shreds that we have.  If we
   could somehow determine P(k), P(k+1), ... P(31), then we could just
   use the 32-32 fast case.  The principal pivot transform gives us a
   way to do exactly that.

   In the 32-32 case, we have:
                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( m_30 )      ( y_30 )
                  ( m_31 )      ( y_31 )

   where m is in the evaluation domain (i.e. P(i) = m_i) and y is in the
   coefficient domain (coefficients of the special basis elements).
   Now, we don't know the last 32-k elements of the m vector, i.e.

                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( ???  )      ( y_30 )
                  ( ???  )      ( y_31 )

   but what we do know is that the last 32-k elements of the y vector
   must be 0 in order for P to have the right order. I.e.

                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( ???  )      (   0  )
                  ( ???  )      (   0  )

   The principal pivot transform solves this type of problem, and for
   certain operators F (including the one we care about here) has a
   complexity of O(n log n), where F is an nxn matrix.  To keep
   consistent with the paper, we multiply through by F and name the
   unknowns, actually solving

                  ( y_0  )      ( m_0  )
                  ( y_1  )      ( m_1  )
            F *   ( ...  )   =  ( ...  )
                  (   0  )      ( x_30 )
                  (   0  )      ( x_31 )

   Once we've solved this, x_k gives us P(k), i.e. the first parity
   shred. If we need more than 32-k parity shreds, then we can just use
   the same strategy as the 32-32 case and use the shifted FFT operation
   to go back from the coefficient domain to the evaluation domain with
   an offset of 32, giving us P(32), P(33), ... P(63) cheaply.

   The paper describes a more general case than what we need, since we
   always know the first k elements of the product vector, and not an
   arbitrary subset of them.  This file only implements the specific
   case. */

#include "fd_reedsol_fft.h"
#ifndef FD_REEDSOL_GF_ARITH_DEFINED
#error "You must include fd_reedsol_arith_gfni.h or fd_reedsol_arith_avx2.h before including this file"
#endif


   /* FD_REEDSOL_GENERATE_PPT: Inserts code to compute the principal
   pivot transform of size n (must be a power of 2, currently only 16
   and 32 are emitted by the code generator) and when you have k known
   elements of the evaluation domain (i.e. k data shreds).  k must be in
   [1,n-1].  The remaining n arguments should be vector variables of
   type gf_t (which is a typedef for wb_t in the AVX case).  These are
   used as input and output, since there's no other good way to return n
   vector values.  As such, this macro is not robust.

   As explained above, the PPT computes the k non-zero elements of the
   coefficient domain, followed by the first n-k parity elements.  If
   the last n-k return values are repalced with zero, they can then be
   used with FD_REEDSOL_GENERATE_FFT and the appropriate shift to
   compute many more parity elements.  The PPT is computed in a
   vectorized fashion, i.e. the PPT of the ith byte is computed and
   stored in the ith byte of the output for each i independently. */

#define FD_REEDSOL_GENERATE_PPT(n, k, ...) FD_REEDSOL_PPT_IMPL_##n##_##k( __VA_ARGS__ )




#define GF_MUL22( inout0, inout1, c00, c01, c10, c11)                               \
  do {                                                                              \
    gf_t temp = GF_ADD( GF_MUL( inout0, c00 ), GF_MUL( inout1, c01 ) );             \
    inout1 = GF_ADD( GF_MUL( inout0, c10 ), GF_MUL( inout1, c11 ) );                \
    inout0 = temp;                                                                  \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_1( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09   , \
    in10, in11, in12, in13, in14, in15)                                                          \
  do {                                                                                           \
    gf_t scratch_2, scratch_4, scratch_8;                                                        \
    scratch_8 = in08;                                                                            \
    in08 = GF_MUL( in08, 1 );                                                                    \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                          \
    scratch_4 = in04;                                                                            \
    in04 = GF_MUL( in04, 1 );                                                                    \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                          \
    scratch_2 = in02;                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                    \
    GF_MUL22( in01, in03, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                          \
    in02 = GF_ADD( GF_MUL( in00, 1 ), in02 );                                                    \
    GF_MUL22( in02, in03, 1, 2, 1, 3 );                                                          \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_2, 0 ), in00 );                                               \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                    \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                     \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                               \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                    \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );             \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                               \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_2( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09   , \
    in10, in11, in12, in13, in14, in15)                                                          \
  do {                                                                                           \
    gf_t scratch_2, scratch_3, scratch_4, scratch_5, scratch_8, scratch_9;                       \
    scratch_8 = in08;                                                                            \
    in08 = GF_MUL( in08, 1 );                                                                    \
    scratch_9 = in09;                                                                            \
    in09 = GF_MUL( in09, 1 );                                                                    \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                          \
    scratch_4 = in04;                                                                            \
    in04 = GF_MUL( in04, 1 );                                                                    \
    scratch_5 = in05;                                                                            \
    in05 = GF_MUL( in05, 1 );                                                                    \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                          \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                          \
    scratch_2 = in02;                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                    \
    scratch_3 = in03;                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                    \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                          \
    in02 = GF_ADD( GF_MUL( in00, 1 ), in02 );                                                    \
    in03 = GF_ADD( GF_MUL( in01, 1 ), in03 );                                                    \
    GF_MUL22( in02, in03, 1, 2, 1, 3 );                                                          \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_2, 0 ), in00 );                                               \
    in01 = GF_MUL( in01, 1 );                                                                    \
    in01 = GF_ADD( GF_MUL( scratch_3, 0 ), in01 );                                               \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                    \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                    \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                     \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                               \
    in01 = GF_MUL( in01, 1 );                                                                    \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                               \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                    \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                    \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );             \
    in00 = GF_MUL( in00, 1 );                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                               \
    in01 = GF_MUL( in01, 1 );                                                                    \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                               \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_3( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, \
    in11, in12, in13, in14, in15)                                                                  \
  do {                                                                                             \
    gf_t scratch_10, scratch_3, scratch_4, scratch_5, scratch_6, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                      \
    scratch_9 = in09;                                                                              \
    in09 = GF_MUL( in09, 1 );                                                                      \
    scratch_10 = in10;                                                                             \
    in10 = GF_MUL( in10, 1 );                                                                      \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                            \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                            \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                            \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                            \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                            \
    scratch_4 = in04;                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                      \
    scratch_5 = in05;                                                                              \
    in05 = GF_MUL( in05, 1 );                                                                      \
    scratch_6 = in06;                                                                              \
    in06 = GF_MUL( in06, 1 );                                                                      \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                            \
    scratch_3 = in03;                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                      \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                            \
    in03 = GF_ADD( GF_MUL( in01, 1 ), in03 );                                                      \
    GF_MUL22( in02, in03, 1, 2, 1, 1 );                                                            \
    GF_MUL22( in00, in02, 1, 0, 1, 1 );                                                            \
    in01 = GF_MUL( in01, 1 );                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_3, 0 ), in01 );                                                 \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                      \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                      \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                       \
    in00 = GF_MUL( in00, 1 );                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                 \
    in01 = GF_MUL( in01, 1 );                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                 \
    in02 = GF_MUL( in02, 1 );                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                 \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                      \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                      \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );               \
    in00 = GF_MUL( in00, 1 );                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                 \
    in01 = GF_MUL( in01, 1 );                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                 \
    in02 = GF_MUL( in02, 1 );                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_4( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, \
    in13, in14, in15)                                                                                          \
  do {                                                                                                         \
    gf_t scratch_10, scratch_11, scratch_4, scratch_5, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                                          \
    in08 = GF_MUL( in08, 1 );                                                                                  \
    scratch_9 = in09;                                                                                          \
    in09 = GF_MUL( in09, 1 );                                                                                  \
    scratch_10 = in10;                                                                                         \
    in10 = GF_MUL( in10, 1 );                                                                                  \
    scratch_11 = in11;                                                                                         \
    in11 = GF_MUL( in11, 1 );                                                                                  \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                        \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                        \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                        \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                        \
    scratch_4 = in04;                                                                                          \
    in04 = GF_MUL( in04, 1 );                                                                                  \
    scratch_5 = in05;                                                                                          \
    in05 = GF_MUL( in05, 1 );                                                                                  \
    scratch_6 = in06;                                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                  \
    scratch_7 = in07;                                                                                          \
    in07 = GF_MUL( in07, 1 );                                                                                  \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                  \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                                  \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                  \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                  \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                  \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                                   \
    in00 = GF_MUL( in00, 1 );                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                             \
    in03 = GF_MUL( in03, 1 );                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                             \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                  \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                  \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                  \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                  \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                           \
    in00 = GF_MUL( in00, 1 );                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                            \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_5( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, \
    in15)                                                                                                                  \
  do {                                                                                                                     \
    gf_t scratch_10, scratch_11, scratch_12, scratch_2, scratch_5, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                                                      \
    in08 = GF_MUL( in08, 1 );                                                                                              \
    scratch_9 = in09;                                                                                                      \
    in09 = GF_MUL( in09, 1 );                                                                                              \
    scratch_10 = in10;                                                                                                     \
    in10 = GF_MUL( in10, 1 );                                                                                              \
    scratch_11 = in11;                                                                                                     \
    in11 = GF_MUL( in11, 1 );                                                                                              \
    scratch_12 = in12;                                                                                                     \
    in12 = GF_MUL( in12, 1 );                                                                                              \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                    \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                    \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                    \
    scratch_5 = in05;                                                                                                      \
    in05 = GF_MUL( in05, 1 );                                                                                              \
    scratch_6 = in06;                                                                                                      \
    in06 = GF_MUL( in06, 1 );                                                                                              \
    scratch_7 = in07;                                                                                                      \
    in07 = GF_MUL( in07, 1 );                                                                                              \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                              \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                              \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                              \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                              \
    scratch_2 = in06;                                                                                                      \
    in06 = GF_MUL( in06, 1 );                                                                                              \
    GF_MUL22( in05, in07, 1, 6, 1, 7 );                                                                                    \
    GF_MUL22( in04, in05, 1, 4, 1, 1 );                                                                                    \
    in06 = GF_ADD( GF_MUL( in04, 1 ), in06 );                                                                              \
    GF_MUL22( in06, in07, 1, 6, 1, 7 );                                                                                    \
    in04 = GF_MUL( in04, 1 );                                                                                              \
    in04 = GF_ADD( GF_MUL( scratch_2, 6 ), in04 );                                                                         \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                    \
    in01 = GF_MUL( in01, 1 );                                                                                              \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                                         \
    in02 = GF_MUL( in02, 1 );                                                                                              \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                         \
    in03 = GF_MUL( in03, 1 );                                                                                              \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                         \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                              \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                              \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                              \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                              \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                              \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                       \
    in00 = GF_MUL( in00, 1 );                                                                                              \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                         \
    in01 = GF_MUL( in01, 1 );                                                                                              \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                         \
    in02 = GF_MUL( in02, 1 );                                                                                              \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                        \
    in03 = GF_MUL( in03, 1 );                                                                                              \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                        \
    in04 = GF_MUL( in04, 1 );                                                                                              \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                        \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_6( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15)      \
  do {                                                                                                                                 \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_2, scratch_3, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                                                                  \
    in08 = GF_MUL( in08, 1 );                                                                                                          \
    scratch_9 = in09;                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                          \
    scratch_10 = in10;                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                          \
    scratch_11 = in11;                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                          \
    scratch_12 = in12;                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                          \
    scratch_13 = in13;                                                                                                                 \
    in13 = GF_MUL( in13, 1 );                                                                                                          \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                \
    scratch_6 = in06;                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                          \
    scratch_7 = in07;                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                          \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                          \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                                          \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                          \
    scratch_2 = in06;                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                          \
    scratch_3 = in07;                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                          \
    GF_MUL22( in04, in05, 5, 4, 1, 1 );                                                                                                \
    in06 = GF_ADD( GF_MUL( in04, 1 ), in06 );                                                                                          \
    in07 = GF_ADD( GF_MUL( in05, 1 ), in07 );                                                                                          \
    GF_MUL22( in06, in07, 1, 6, 1, 7 );                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                          \
    in04 = GF_ADD( GF_MUL( scratch_2, 6 ), in04 );                                                                                     \
    in05 = GF_MUL( in05, 1 );                                                                                                          \
    in05 = GF_ADD( GF_MUL( scratch_3, 6 ), in05 );                                                                                     \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                                \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                                                                \
    in02 = GF_MUL( in02, 1 );                                                                                                          \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                                     \
    in03 = GF_MUL( in03, 1 );                                                                                                          \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                                     \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                          \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                          \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                          \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                          \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                          \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                          \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                   \
    in00 = GF_MUL( in00, 1 );                                                                                                          \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                     \
    in01 = GF_MUL( in01, 1 );                                                                                                          \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                     \
    in02 = GF_MUL( in02, 1 );                                                                                                          \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                    \
    in03 = GF_MUL( in03, 1 );                                                                                                          \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                    \
    in04 = GF_MUL( in04, 1 );                                                                                                          \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                    \
    in05 = GF_MUL( in05, 1 );                                                                                                          \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                    \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_7( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14 , \
    in15)                                                                                                                    \
  do {                                                                                                                       \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_3, scratch_7, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                                                        \
    in08 = GF_MUL( in08, 1 );                                                                                                \
    scratch_9 = in09;                                                                                                        \
    in09 = GF_MUL( in09, 1 );                                                                                                \
    scratch_10 = in10;                                                                                                       \
    in10 = GF_MUL( in10, 1 );                                                                                                \
    scratch_11 = in11;                                                                                                       \
    in11 = GF_MUL( in11, 1 );                                                                                                \
    scratch_12 = in12;                                                                                                       \
    in12 = GF_MUL( in12, 1 );                                                                                                \
    scratch_13 = in13;                                                                                                       \
    in13 = GF_MUL( in13, 1 );                                                                                                \
    scratch_14 = in14;                                                                                                       \
    in14 = GF_MUL( in14, 1 );                                                                                                \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                      \
    scratch_7 = in07;                                                                                                        \
    in07 = GF_MUL( in07, 1 );                                                                                                \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                \
    scratch_3 = in07;                                                                                                        \
    in07 = GF_MUL( in07, 1 );                                                                                                \
    GF_MUL22( in04, in05, 5, 4, 1, 1 );                                                                                      \
    in07 = GF_ADD( GF_MUL( in05, 1 ), in07 );                                                                                \
    GF_MUL22( in06, in07, 1, 6, 1, 1 );                                                                                      \
    GF_MUL22( in04, in06, 7, 6, 1, 1 );                                                                                      \
    in05 = GF_MUL( in05, 1 );                                                                                                \
    in05 = GF_ADD( GF_MUL( scratch_3, 6 ), in05 );                                                                           \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                      \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                                                      \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                                                      \
    in03 = GF_MUL( in03, 1 );                                                                                                \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                           \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                         \
    in00 = GF_MUL( in00, 1 );                                                                                                \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                           \
    in01 = GF_MUL( in01, 1 );                                                                                                \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                           \
    in02 = GF_MUL( in02, 1 );                                                                                                \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                          \
    in03 = GF_MUL( in03, 1 );                                                                                                \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                          \
    in04 = GF_MUL( in04, 1 );                                                                                                \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                          \
    in05 = GF_MUL( in05, 1 );                                                                                                \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                                \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                          \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_8( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12   , \
    in13, in14, in15)                                                                                              \
  do {                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_8, scratch_9;             \
    scratch_8 = in08;                                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                                      \
    scratch_9 = in09;                                                                                              \
    in09 = GF_MUL( in09, 1 );                                                                                      \
    scratch_10 = in10;                                                                                             \
    in10 = GF_MUL( in10, 1 );                                                                                      \
    scratch_11 = in11;                                                                                             \
    in11 = GF_MUL( in11, 1 );                                                                                      \
    scratch_12 = in12;                                                                                             \
    in12 = GF_MUL( in12, 1 );                                                                                      \
    scratch_13 = in13;                                                                                             \
    in13 = GF_MUL( in13, 1 );                                                                                      \
    scratch_14 = in14;                                                                                             \
    in14 = GF_MUL( in14, 1 );                                                                                      \
    scratch_15 = in15;                                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                              \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                      \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                      \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                      \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                      \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                      \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                      \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                      \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                               \
    in00 = GF_MUL( in00, 1 );                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                \
    in03 = GF_MUL( in03, 1 );                                                                                      \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_9( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14  , \
    in15)                                                                                                                     \
  do {                                                                                                                        \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_2, scratch_4, scratch_9;             \
    scratch_9 = in09;                                                                                                         \
    in09 = GF_MUL( in09, 1 );                                                                                                 \
    scratch_10 = in10;                                                                                                        \
    in10 = GF_MUL( in10, 1 );                                                                                                 \
    scratch_11 = in11;                                                                                                        \
    in11 = GF_MUL( in11, 1 );                                                                                                 \
    scratch_12 = in12;                                                                                                        \
    in12 = GF_MUL( in12, 1 );                                                                                                 \
    scratch_13 = in13;                                                                                                        \
    in13 = GF_MUL( in13, 1 );                                                                                                 \
    scratch_14 = in14;                                                                                                        \
    in14 = GF_MUL( in14, 1 );                                                                                                 \
    scratch_15 = in15;                                                                                                        \
    in15 = GF_MUL( in15, 1 );                                                                                                 \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                         \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                 \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                 \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                 \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                 \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                 \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                 \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                 \
    scratch_4 = in12;                                                                                                         \
    in12 = GF_MUL( in12, 1 );                                                                                                 \
    GF_MUL22( in09, in13, 1, 22, 1, 23 );                                                                                     \
    GF_MUL22( in10, in14, 1, 22, 1, 23 );                                                                                     \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                     \
    scratch_2 = in10;                                                                                                         \
    in10 = GF_MUL( in10, 1 );                                                                                                 \
    GF_MUL22( in09, in11, 1, 28, 1, 29 );                                                                                     \
    GF_MUL22( in08, in09, 1, 8, 1, 1 );                                                                                       \
    in10 = GF_ADD( GF_MUL( in08, 1 ), in10 );                                                                                 \
    GF_MUL22( in10, in11, 1, 10, 1, 11 );                                                                                     \
    in08 = GF_MUL( in08, 1 );                                                                                                 \
    in08 = GF_ADD( GF_MUL( scratch_2, 28 ), in08 );                                                                           \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                 \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                 \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                           \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                       \
    in01 = GF_MUL( in01, 1 );                                                                                                 \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                                                 \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                           \
    in03 = GF_MUL( in03, 1 );                                                                                                 \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                           \
    in04 = GF_MUL( in04, 1 );                                                                                                 \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                           \
    in05 = GF_MUL( in05, 1 );                                                                                                 \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                           \
    in06 = GF_MUL( in06, 1 );                                                                                                 \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                           \
    in07 = GF_MUL( in07, 1 );                                                                                                 \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                           \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_10( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15)       \
  do {                                                                                                                                   \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_2, scratch_3, scratch_4, scratch_5;             \
    scratch_10 = in10;                                                                                                                   \
    in10 = GF_MUL( in10, 1 );                                                                                                            \
    scratch_11 = in11;                                                                                                                   \
    in11 = GF_MUL( in11, 1 );                                                                                                            \
    scratch_12 = in12;                                                                                                                   \
    in12 = GF_MUL( in12, 1 );                                                                                                            \
    scratch_13 = in13;                                                                                                                   \
    in13 = GF_MUL( in13, 1 );                                                                                                            \
    scratch_14 = in14;                                                                                                                   \
    in14 = GF_MUL( in14, 1 );                                                                                                            \
    scratch_15 = in15;                                                                                                                   \
    in15 = GF_MUL( in15, 1 );                                                                                                            \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                    \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                            \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                            \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                            \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                            \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                            \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                            \
    scratch_4 = in12;                                                                                                                    \
    in12 = GF_MUL( in12, 1 );                                                                                                            \
    scratch_5 = in13;                                                                                                                    \
    in13 = GF_MUL( in13, 1 );                                                                                                            \
    GF_MUL22( in10, in14, 1, 22, 1, 23 );                                                                                                \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                                \
    scratch_2 = in10;                                                                                                                    \
    in10 = GF_MUL( in10, 1 );                                                                                                            \
    scratch_3 = in11;                                                                                                                    \
    in11 = GF_MUL( in11, 1 );                                                                                                            \
    GF_MUL22( in08, in09, 9, 8, 1, 1 );                                                                                                  \
    in10 = GF_ADD( GF_MUL( in08, 1 ), in10 );                                                                                            \
    in11 = GF_ADD( GF_MUL( in09, 1 ), in11 );                                                                                            \
    GF_MUL22( in10, in11, 1, 10, 1, 11 );                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                            \
    in08 = GF_ADD( GF_MUL( scratch_2, 28 ), in08 );                                                                                      \
    in09 = GF_MUL( in09, 1 );                                                                                                            \
    in09 = GF_ADD( GF_MUL( scratch_3, 28 ), in09 );                                                                                      \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                            \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                            \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                            \
    in08 = GF_MUL( in08, 1 );                                                                                                            \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                                      \
    in09 = GF_MUL( in09, 1 );                                                                                                            \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                                      \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                  \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                  \
    in02 = GF_MUL( in02, 1 );                                                                                                            \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                      \
    in03 = GF_MUL( in03, 1 );                                                                                                            \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                      \
    in04 = GF_MUL( in04, 1 );                                                                                                            \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                      \
    in05 = GF_MUL( in05, 1 );                                                                                                            \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                      \
    in06 = GF_MUL( in06, 1 );                                                                                                            \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                      \
    in07 = GF_MUL( in07, 1 );                                                                                                            \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                      \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_11( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, \
    in15)                                                                                                                    \
  do {                                                                                                                       \
    gf_t scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_3, scratch_4, scratch_5, scratch_6;             \
    scratch_11 = in11;                                                                                                       \
    in11 = GF_MUL( in11, 1 );                                                                                                \
    scratch_12 = in12;                                                                                                       \
    in12 = GF_MUL( in12, 1 );                                                                                                \
    scratch_13 = in13;                                                                                                       \
    in13 = GF_MUL( in13, 1 );                                                                                                \
    scratch_14 = in14;                                                                                                       \
    in14 = GF_MUL( in14, 1 );                                                                                                \
    scratch_15 = in15;                                                                                                       \
    in15 = GF_MUL( in15, 1 );                                                                                                \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                        \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                \
    scratch_4 = in12;                                                                                                        \
    in12 = GF_MUL( in12, 1 );                                                                                                \
    scratch_5 = in13;                                                                                                        \
    in13 = GF_MUL( in13, 1 );                                                                                                \
    scratch_6 = in14;                                                                                                        \
    in14 = GF_MUL( in14, 1 );                                                                                                \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                    \
    scratch_3 = in11;                                                                                                        \
    in11 = GF_MUL( in11, 1 );                                                                                                \
    GF_MUL22( in08, in09, 9, 8, 1, 1 );                                                                                      \
    in11 = GF_ADD( GF_MUL( in09, 1 ), in11 );                                                                                \
    GF_MUL22( in10, in11, 1, 10, 1, 1 );                                                                                     \
    GF_MUL22( in08, in10, 29, 28, 1, 1 );                                                                                    \
    in09 = GF_MUL( in09, 1 );                                                                                                \
    in09 = GF_ADD( GF_MUL( scratch_3, 28 ), in09 );                                                                          \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                                \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                          \
    in09 = GF_MUL( in09, 1 );                                                                                                \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                          \
    in10 = GF_MUL( in10, 1 );                                                                                                \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                                          \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                      \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                      \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                      \
    in03 = GF_MUL( in03, 1 );                                                                                                \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                          \
    in04 = GF_MUL( in04, 1 );                                                                                                \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                          \
    in05 = GF_MUL( in05, 1 );                                                                                                \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                                \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                          \
    in07 = GF_MUL( in07, 1 );                                                                                                \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                          \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_12( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, \
    in13, in14, in15)                                                                                            \
  do {                                                                                                           \
    gf_t scratch_12, scratch_13, scratch_14, scratch_15, scratch_4, scratch_5, scratch_6, scratch_7;             \
    scratch_12 = in12;                                                                                           \
    in12 = GF_MUL( in12, 1 );                                                                                    \
    scratch_13 = in13;                                                                                           \
    in13 = GF_MUL( in13, 1 );                                                                                    \
    scratch_14 = in14;                                                                                           \
    in14 = GF_MUL( in14, 1 );                                                                                    \
    scratch_15 = in15;                                                                                           \
    in15 = GF_MUL( in15, 1 );                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                            \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                    \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                    \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                    \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                    \
    scratch_4 = in12;                                                                                            \
    in12 = GF_MUL( in12, 1 );                                                                                    \
    scratch_5 = in13;                                                                                            \
    in13 = GF_MUL( in13, 1 );                                                                                    \
    scratch_6 = in14;                                                                                            \
    in14 = GF_MUL( in14, 1 );                                                                                    \
    scratch_7 = in15;                                                                                            \
    in15 = GF_MUL( in15, 1 );                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                                    \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                    \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                    \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                    \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                                    \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                    \
    in08 = GF_MUL( in08, 1 );                                                                                    \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                              \
    in09 = GF_MUL( in09, 1 );                                                                                    \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                              \
    in10 = GF_MUL( in10, 1 );                                                                                    \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                              \
    in11 = GF_MUL( in11, 1 );                                                                                    \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                              \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                          \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                          \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                          \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                          \
    in04 = GF_MUL( in04, 1 );                                                                                    \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                              \
    in05 = GF_MUL( in05, 1 );                                                                                    \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                              \
    in06 = GF_MUL( in06, 1 );                                                                                    \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                              \
    in07 = GF_MUL( in07, 1 );                                                                                    \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                              \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_13( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, \
    in11, in12, in13, in14, in15)                                                                    \
  do {                                                                                               \
    gf_t scratch_13, scratch_14, scratch_15, scratch_2, scratch_5, scratch_6, scratch_7;             \
    scratch_13 = in13;                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                        \
    scratch_14 = in14;                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                        \
    scratch_15 = in15;                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                        \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                        \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                        \
    scratch_5 = in13;                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                        \
    scratch_6 = in14;                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                        \
    scratch_7 = in15;                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                        \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                        \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                        \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                        \
    scratch_2 = in14;                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                        \
    GF_MUL22( in13, in15, 1, 26, 1, 27 );                                                            \
    GF_MUL22( in12, in13, 1, 12, 1, 1 );                                                             \
    in14 = GF_ADD( GF_MUL( in12, 1 ), in14 );                                                        \
    GF_MUL22( in14, in15, 1, 14, 1, 15 );                                                            \
    in12 = GF_MUL( in12, 1 );                                                                        \
    in12 = GF_ADD( GF_MUL( scratch_2, 26 ), in12 );                                                  \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                            \
    in09 = GF_MUL( in09, 1 );                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                  \
    in10 = GF_MUL( in10, 1 );                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                  \
    in11 = GF_MUL( in11, 1 );                                                                        \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                  \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                              \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                              \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                              \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                              \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                              \
    in05 = GF_MUL( in05, 1 );                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                  \
    in06 = GF_MUL( in06, 1 );                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                  \
    in07 = GF_MUL( in07, 1 );                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                  \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_14( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09   , \
    in10, in11, in12, in13, in14, in15)                                                           \
  do {                                                                                            \
    gf_t scratch_14, scratch_15, scratch_2, scratch_3, scratch_6, scratch_7;                      \
    scratch_14 = in14;                                                                            \
    in14 = GF_MUL( in14, 1 );                                                                     \
    scratch_15 = in15;                                                                            \
    in15 = GF_MUL( in15, 1 );                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );             \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                     \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                     \
    scratch_6 = in14;                                                                             \
    in14 = GF_MUL( in14, 1 );                                                                     \
    scratch_7 = in15;                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                     \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                     \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                     \
    scratch_2 = in14;                                                                             \
    in14 = GF_MUL( in14, 1 );                                                                     \
    scratch_3 = in15;                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                     \
    GF_MUL22( in12, in13, 13, 12, 1, 1 );                                                         \
    in14 = GF_ADD( GF_MUL( in12, 1 ), in14 );                                                     \
    in15 = GF_ADD( GF_MUL( in13, 1 ), in15 );                                                     \
    GF_MUL22( in14, in15, 1, 14, 1, 15 );                                                         \
    in12 = GF_MUL( in12, 1 );                                                                     \
    in12 = GF_ADD( GF_MUL( scratch_2, 26 ), in12 );                                               \
    in13 = GF_MUL( in13, 1 );                                                                     \
    in13 = GF_ADD( GF_MUL( scratch_3, 26 ), in13 );                                               \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                         \
    GF_MUL22( in09, in13, 23, 22, 1, 1 );                                                         \
    in10 = GF_MUL( in10, 1 );                                                                     \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                               \
    in11 = GF_MUL( in11, 1 );                                                                     \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                               \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                           \
    in06 = GF_MUL( in06, 1 );                                                                     \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                               \
    in07 = GF_MUL( in07, 1 );                                                                     \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                               \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_16_15( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09   , \
    in10, in11, in12, in13, in14, in15)                                                           \
  do {                                                                                            \
    gf_t scratch_15, scratch_3, scratch_7;                                                        \
    scratch_15 = in15;                                                                            \
    in15 = GF_MUL( in15, 1 );                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );             \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                     \
    scratch_7 = in15;                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                     \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                     \
    scratch_3 = in15;                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                     \
    GF_MUL22( in12, in13, 13, 12, 1, 1 );                                                         \
    in15 = GF_ADD( GF_MUL( in13, 1 ), in15 );                                                     \
    GF_MUL22( in14, in15, 1, 14, 1, 1 );                                                          \
    GF_MUL22( in12, in14, 27, 26, 1, 1 );                                                         \
    in13 = GF_MUL( in13, 1 );                                                                     \
    in13 = GF_ADD( GF_MUL( scratch_3, 26 ), in13 );                                               \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                         \
    GF_MUL22( in09, in13, 23, 22, 1, 1 );                                                         \
    GF_MUL22( in10, in14, 23, 22, 1, 1 );                                                         \
    in11 = GF_MUL( in11, 1 );                                                                     \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                               \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                           \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                           \
    in07 = GF_MUL( in07, 1 );                                                                     \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                               \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_1( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                                  \
  do {                                                                                                                                             \
    gf_t scratch_16, scratch_2, scratch_4, scratch_8;                                                                                              \
    scratch_16 = in16;                                                                                                                             \
    in16 = GF_MUL( in16, 1 );                                                                                                                      \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                            \
    scratch_8 = in08;                                                                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                                                                      \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                            \
    scratch_4 = in04;                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                      \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                                                                            \
    scratch_2 = in02;                                                                                                                              \
    in02 = GF_MUL( in02, 1 );                                                                                                                      \
    GF_MUL22( in01, in03, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                                                                            \
    in02 = GF_ADD( GF_MUL( in00, 1 ), in02 );                                                                                                      \
    GF_MUL22( in02, in03, 1, 2, 1, 3 );                                                                                                            \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_2, 0 ), in00 );                                                                                                 \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                                                                       \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                                                                 \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );             \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_2( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                                  \
  do {                                                                                                                                             \
    gf_t scratch_16, scratch_17, scratch_2, scratch_3, scratch_4, scratch_5, scratch_8, scratch_9;                                                 \
    scratch_16 = in16;                                                                                                                             \
    in16 = GF_MUL( in16, 1 );                                                                                                                      \
    scratch_17 = in17;                                                                                                                             \
    in17 = GF_MUL( in17, 1 );                                                                                                                      \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                            \
    scratch_8 = in08;                                                                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                                                                      \
    scratch_9 = in09;                                                                                                                              \
    in09 = GF_MUL( in09, 1 );                                                                                                                      \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                            \
    scratch_4 = in04;                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                      \
    scratch_5 = in05;                                                                                                                              \
    in05 = GF_MUL( in05, 1 );                                                                                                                      \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                                                                            \
    scratch_2 = in02;                                                                                                                              \
    in02 = GF_MUL( in02, 1 );                                                                                                                      \
    scratch_3 = in03;                                                                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                                                                      \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                                                                            \
    in02 = GF_ADD( GF_MUL( in00, 1 ), in02 );                                                                                                      \
    in03 = GF_ADD( GF_MUL( in01, 1 ), in03 );                                                                                                      \
    GF_MUL22( in02, in03, 1, 2, 1, 3 );                                                                                                            \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_2, 0 ), in00 );                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_3, 0 ), in01 );                                                                                                 \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                                                                      \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                                                                       \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                                                                 \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                      \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                      \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );             \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_3( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                                  \
  do {                                                                                                                                             \
    gf_t scratch_10, scratch_16, scratch_17, scratch_18, scratch_3, scratch_4, scratch_5, scratch_6, scratch_8, scratch_9;                         \
    scratch_16 = in16;                                                                                                                             \
    in16 = GF_MUL( in16, 1 );                                                                                                                      \
    scratch_17 = in17;                                                                                                                             \
    in17 = GF_MUL( in17, 1 );                                                                                                                      \
    scratch_18 = in18;                                                                                                                             \
    in18 = GF_MUL( in18, 1 );                                                                                                                      \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                            \
    scratch_8 = in08;                                                                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                                                                      \
    scratch_9 = in09;                                                                                                                              \
    in09 = GF_MUL( in09, 1 );                                                                                                                      \
    scratch_10 = in10;                                                                                                                             \
    in10 = GF_MUL( in10, 1 );                                                                                                                      \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                            \
    scratch_4 = in04;                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                      \
    scratch_5 = in05;                                                                                                                              \
    in05 = GF_MUL( in05, 1 );                                                                                                                      \
    scratch_6 = in06;                                                                                                                              \
    in06 = GF_MUL( in06, 1 );                                                                                                                      \
    GF_MUL22( in03, in07, 1, 0, 1, 1 );                                                                                                            \
    scratch_3 = in03;                                                                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                                                                      \
    GF_MUL22( in00, in01, 1, 0, 1, 1 );                                                                                                            \
    in03 = GF_ADD( GF_MUL( in01, 1 ), in03 );                                                                                                      \
    GF_MUL22( in02, in03, 1, 2, 1, 1 );                                                                                                            \
    GF_MUL22( in00, in02, 1, 0, 1, 1 );                                                                                                            \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_3, 0 ), in01 );                                                                                                 \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                                                                      \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                                                      \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                                                                       \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                                                 \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                      \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                      \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                      \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                      \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );             \
    in00 = GF_MUL( in00, 1 );                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                \
    in01 = GF_MUL( in01, 1 );                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                \
    in02 = GF_MUL( in02, 1 );                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_4( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, \
    in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                                                          \
  do {                                                                                                                                                         \
    gf_t scratch_10, scratch_11, scratch_16, scratch_17, scratch_18, scratch_19, scratch_4, scratch_5, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_16 = in16;                                                                                                                                         \
    in16 = GF_MUL( in16, 1 );                                                                                                                                  \
    scratch_17 = in17;                                                                                                                                         \
    in17 = GF_MUL( in17, 1 );                                                                                                                                  \
    scratch_18 = in18;                                                                                                                                         \
    in18 = GF_MUL( in18, 1 );                                                                                                                                  \
    scratch_19 = in19;                                                                                                                                         \
    in19 = GF_MUL( in19, 1 );                                                                                                                                  \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                        \
    scratch_8 = in08;                                                                                                                                          \
    in08 = GF_MUL( in08, 1 );                                                                                                                                  \
    scratch_9 = in09;                                                                                                                                          \
    in09 = GF_MUL( in09, 1 );                                                                                                                                  \
    scratch_10 = in10;                                                                                                                                         \
    in10 = GF_MUL( in10, 1 );                                                                                                                                  \
    scratch_11 = in11;                                                                                                                                         \
    in11 = GF_MUL( in11, 1 );                                                                                                                                  \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                                        \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                                        \
    scratch_4 = in04;                                                                                                                                          \
    in04 = GF_MUL( in04, 1 );                                                                                                                                  \
    scratch_5 = in05;                                                                                                                                          \
    in05 = GF_MUL( in05, 1 );                                                                                                                                  \
    scratch_6 = in06;                                                                                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                                                                  \
    scratch_7 = in07;                                                                                                                                          \
    in07 = GF_MUL( in07, 1 );                                                                                                                                  \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                                                  \
    in04 = GF_ADD( GF_MUL( in00, 1 ), in04 );                                                                                                                  \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                                                                  \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                                                                  \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                                                  \
    FD_REEDSOL_GENERATE_FFT( 4, 4, in04, in05, in06, in07 );                                                                                                   \
    in00 = GF_MUL( in00, 1 );                                                                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_4, 0 ), in00 );                                                                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                                                             \
    in03 = GF_MUL( in03, 1 );                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                                                             \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                                  \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                  \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                  \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                  \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                           \
    in00 = GF_MUL( in00, 1 );                                                                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                            \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                  \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                  \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                  \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                  \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                         \
    in00 = GF_MUL( in00, 1 );                                                                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                            \
    in01 = GF_MUL( in01, 1 );                                                                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                            \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_5( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, \
    in25, in26, in27, in28, in29, in30, in31)                                                                                                                                          \
  do {                                                                                                                                                                                 \
    gf_t scratch_10, scratch_11, scratch_12, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_5, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_16 = in16;                                                                                                                                                                 \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                          \
    scratch_17 = in17;                                                                                                                                                                 \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                          \
    scratch_18 = in18;                                                                                                                                                                 \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                          \
    scratch_19 = in19;                                                                                                                                                                 \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                          \
    scratch_20 = in20;                                                                                                                                                                 \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                          \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                \
    scratch_8 = in08;                                                                                                                                                                  \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                          \
    scratch_9 = in09;                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                          \
    scratch_10 = in10;                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                          \
    scratch_11 = in11;                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                          \
    scratch_12 = in12;                                                                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                          \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                                                                \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                                                                \
    scratch_5 = in05;                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                          \
    scratch_6 = in06;                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                          \
    scratch_7 = in07;                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                          \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                                                                          \
    in05 = GF_ADD( GF_MUL( in01, 1 ), in05 );                                                                                                                                          \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                                                                                          \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                                                                          \
    scratch_2 = in06;                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                          \
    GF_MUL22( in05, in07, 1, 6, 1, 7 );                                                                                                                                                \
    GF_MUL22( in04, in05, 1, 4, 1, 1 );                                                                                                                                                \
    in06 = GF_ADD( GF_MUL( in04, 1 ), in06 );                                                                                                                                          \
    GF_MUL22( in06, in07, 1, 6, 1, 7 );                                                                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                          \
    in04 = GF_ADD( GF_MUL( scratch_2, 6 ), in04 );                                                                                                                                     \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                                                                                \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                          \
    in01 = GF_ADD( GF_MUL( scratch_5, 0 ), in01 );                                                                                                                                     \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                          \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                                                                                     \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                          \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                                                                                     \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                                                          \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                                          \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                          \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                          \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                          \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                                                   \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                          \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                                                     \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                          \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                                                     \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                          \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                    \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                          \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                    \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                          \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                    \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                          \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                          \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                          \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                          \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                          \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                 \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                          \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                    \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                          \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                    \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                          \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                    \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                          \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                    \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                          \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                    \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_6( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, \
    in29, in30, in31)                                                                                                                                                                                          \
  do {                                                                                                                                                                                                         \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_3, scratch_6, scratch_7, scratch_8, scratch_9;             \
    scratch_16 = in16;                                                                                                                                                                                         \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                  \
    scratch_17 = in17;                                                                                                                                                                                         \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                  \
    scratch_18 = in18;                                                                                                                                                                                         \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                  \
    scratch_19 = in19;                                                                                                                                                                                         \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                  \
    scratch_20 = in20;                                                                                                                                                                                         \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                  \
    scratch_21 = in21;                                                                                                                                                                                         \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                  \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                        \
    scratch_8 = in08;                                                                                                                                                                                          \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                  \
    scratch_9 = in09;                                                                                                                                                                                          \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                  \
    scratch_10 = in10;                                                                                                                                                                                         \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                  \
    scratch_11 = in11;                                                                                                                                                                                         \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                  \
    scratch_12 = in12;                                                                                                                                                                                         \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                  \
    scratch_13 = in13;                                                                                                                                                                                         \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                  \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                                                                                        \
    scratch_6 = in06;                                                                                                                                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                  \
    scratch_7 = in07;                                                                                                                                                                                          \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                  \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                                                                                                  \
    in06 = GF_ADD( GF_MUL( in02, 1 ), in06 );                                                                                                                                                                  \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                                                                                                  \
    scratch_2 = in06;                                                                                                                                                                                          \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                  \
    scratch_3 = in07;                                                                                                                                                                                          \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                  \
    GF_MUL22( in04, in05, 5, 4, 1, 1 );                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( in04, 1 ), in06 );                                                                                                                                                                  \
    in07 = GF_ADD( GF_MUL( in05, 1 ), in07 );                                                                                                                                                                  \
    GF_MUL22( in06, in07, 1, 6, 1, 7 );                                                                                                                                                                        \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                  \
    in04 = GF_ADD( GF_MUL( scratch_2, 6 ), in04 );                                                                                                                                                             \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                  \
    in05 = GF_ADD( GF_MUL( scratch_3, 6 ), in05 );                                                                                                                                                             \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                                                                                                                                        \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_6, 0 ), in02 );                                                                                                                                                             \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                                                                                                             \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                                                                                  \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                                                                  \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                                                  \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                  \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                  \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                  \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                                                                           \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                            \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                  \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                            \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                  \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                            \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                  \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                  \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                  \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                  \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                  \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                  \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                         \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                  \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                            \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                  \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                  \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                  \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                            \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                  \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                            \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                  \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                            \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_7( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28 , \
    in29, in30, in31)                                                                                                                                                                                            \
  do {                                                                                                                                                                                                           \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_3, scratch_7, scratch_8, scratch_9;             \
    scratch_16 = in16;                                                                                                                                                                                           \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                    \
    scratch_17 = in17;                                                                                                                                                                                           \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                    \
    scratch_18 = in18;                                                                                                                                                                                           \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                    \
    scratch_19 = in19;                                                                                                                                                                                           \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                    \
    scratch_20 = in20;                                                                                                                                                                                           \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                    \
    scratch_21 = in21;                                                                                                                                                                                           \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                    \
    scratch_22 = in22;                                                                                                                                                                                           \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                    \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                          \
    scratch_8 = in08;                                                                                                                                                                                            \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                    \
    scratch_9 = in09;                                                                                                                                                                                            \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                    \
    scratch_10 = in10;                                                                                                                                                                                           \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                    \
    scratch_11 = in11;                                                                                                                                                                                           \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                    \
    scratch_12 = in12;                                                                                                                                                                                           \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                    \
    scratch_13 = in13;                                                                                                                                                                                           \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                    \
    scratch_14 = in14;                                                                                                                                                                                           \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                    \
    GF_MUL22( in07, in15, 1, 0, 1, 1 );                                                                                                                                                                          \
    scratch_7 = in07;                                                                                                                                                                                            \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 4, 0, in00, in01, in02, in03 );                                                                                                                                                    \
    in07 = GF_ADD( GF_MUL( in03, 1 ), in07 );                                                                                                                                                                    \
    scratch_3 = in07;                                                                                                                                                                                            \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                    \
    GF_MUL22( in04, in05, 5, 4, 1, 1 );                                                                                                                                                                          \
    in07 = GF_ADD( GF_MUL( in05, 1 ), in07 );                                                                                                                                                                    \
    GF_MUL22( in06, in07, 1, 6, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in04, in06, 7, 6, 1, 1 );                                                                                                                                                                          \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                    \
    in05 = GF_ADD( GF_MUL( scratch_3, 6 ), in05 );                                                                                                                                                               \
    GF_MUL22( in00, in04, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in01, in05, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in02, in06, 1, 0, 1, 1 );                                                                                                                                                                          \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                    \
    in03 = GF_ADD( GF_MUL( scratch_7, 0 ), in03 );                                                                                                                                                               \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                                                                                    \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                                                                    \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                                                    \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                    \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                    \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                    \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                                                                             \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                                                                               \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                    \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                                                                               \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                    \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                    \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                    \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                              \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                    \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                              \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                    \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                              \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                    \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                    \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                    \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                    \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                    \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                    \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                           \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                    \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                              \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                    \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                              \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                    \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                    \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                    \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                              \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                    \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                              \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                    \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                              \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_8( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_8, scratch_9;             \
    scratch_16 = in16;                                                                                                                                                                                             \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    scratch_17 = in17;                                                                                                                                                                                             \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    scratch_18 = in18;                                                                                                                                                                                             \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    scratch_19 = in19;                                                                                                                                                                                             \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    scratch_20 = in20;                                                                                                                                                                                             \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_21 = in21;                                                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                            \
    scratch_8 = in08;                                                                                                                                                                                              \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    scratch_9 = in09;                                                                                                                                                                                              \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    scratch_10 = in10;                                                                                                                                                                                             \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    scratch_11 = in11;                                                                                                                                                                                             \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    scratch_12 = in12;                                                                                                                                                                                             \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    scratch_13 = in13;                                                                                                                                                                                             \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    scratch_14 = in14;                                                                                                                                                                                             \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    scratch_15 = in15;                                                                                                                                                                                             \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                              \
    in08 = GF_ADD( GF_MUL( in00, 1 ), in08 );                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 8, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_8, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                                                \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                      \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                             \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                      \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                      \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                      \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_9( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28    , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24;             \
    gf_t scratch_4, scratch_9;                                                                                                                                                                                      \
    scratch_16 = in16;                                                                                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                             \
    scratch_9 = in09;                                                                                                                                                                                               \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    scratch_10 = in10;                                                                                                                                                                                              \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    scratch_11 = in11;                                                                                                                                                                                              \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    scratch_12 = in12;                                                                                                                                                                                              \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    scratch_13 = in13;                                                                                                                                                                                              \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    scratch_14 = in14;                                                                                                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_15 = in15;                                                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                               \
    in09 = GF_ADD( GF_MUL( in01, 1 ), in09 );                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                       \
    scratch_4 = in12;                                                                                                                                                                                               \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    GF_MUL22( in09, in13, 1, 22, 1, 23 );                                                                                                                                                                           \
    GF_MUL22( in10, in14, 1, 22, 1, 23 );                                                                                                                                                                           \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                                                                                                           \
    scratch_2 = in10;                                                                                                                                                                                               \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    GF_MUL22( in09, in11, 1, 28, 1, 29 );                                                                                                                                                                           \
    GF_MUL22( in08, in09, 1, 8, 1, 1 );                                                                                                                                                                             \
    in10 = GF_ADD( GF_MUL( in08, 1 ), in10 );                                                                                                                                                                       \
    GF_MUL22( in10, in11, 1, 10, 1, 11 );                                                                                                                                                                           \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_2, 28 ), in08 );                                                                                                                                                                 \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                                                                                                       \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                                                                                                                 \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_9, 0 ), in01 );                                                                                                                                                                  \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                       \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                              \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                       \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_10( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24;             \
    gf_t scratch_25, scratch_3, scratch_4, scratch_5;                                                                                                                                                               \
    scratch_16 = in16;                                                                                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    scratch_25 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                       \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                             \
    scratch_10 = in10;                                                                                                                                                                                              \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    scratch_11 = in11;                                                                                                                                                                                              \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    scratch_12 = in12;                                                                                                                                                                                              \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    scratch_13 = in13;                                                                                                                                                                                              \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    scratch_14 = in14;                                                                                                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_15 = in15;                                                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                               \
    in10 = GF_ADD( GF_MUL( in02, 1 ), in10 );                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                       \
    scratch_4 = in12;                                                                                                                                                                                               \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    scratch_5 = in13;                                                                                                                                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    GF_MUL22( in10, in14, 1, 22, 1, 23 );                                                                                                                                                                           \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                                                                                                           \
    scratch_2 = in10;                                                                                                                                                                                               \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    scratch_3 = in11;                                                                                                                                                                                               \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    GF_MUL22( in08, in09, 9, 8, 1, 1 );                                                                                                                                                                             \
    in10 = GF_ADD( GF_MUL( in08, 1 ), in10 );                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( in09, 1 ), in11 );                                                                                                                                                                       \
    GF_MUL22( in10, in11, 1, 10, 1, 11 );                                                                                                                                                                           \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_2, 28 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_3, 28 ), in09 );                                                                                                                                                                 \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                                                                                                       \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                                                                                                                 \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                             \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_10, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                       \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                              \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                       \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_11( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28    , \
    in29, in30, in31)                                                                                                                                                                                                \
  do {                                                                                                                                                                                                               \
    gf_t scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26;             \
    gf_t scratch_3, scratch_4, scratch_5, scratch_6;                                                                                                                                                                 \
    scratch_16 = in16;                                                                                                                                                                                               \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                        \
    scratch_17 = in17;                                                                                                                                                                                               \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                        \
    scratch_18 = in18;                                                                                                                                                                                               \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                        \
    scratch_19 = in19;                                                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                        \
    scratch_20 = in20;                                                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                        \
    scratch_21 = in21;                                                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                        \
    scratch_22 = in22;                                                                                                                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                        \
    scratch_23 = in23;                                                                                                                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                        \
    scratch_24 = in24;                                                                                                                                                                                               \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                        \
    scratch_25 = in25;                                                                                                                                                                                               \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                        \
    scratch_26 = in26;                                                                                                                                                                                               \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                        \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                              \
    scratch_11 = in11;                                                                                                                                                                                               \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                        \
    scratch_12 = in12;                                                                                                                                                                                               \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                        \
    scratch_13 = in13;                                                                                                                                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                        \
    scratch_14 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                        \
    scratch_15 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                                \
    in11 = GF_ADD( GF_MUL( in03, 1 ), in11 );                                                                                                                                                                        \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                        \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                        \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                        \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                        \
    scratch_4 = in12;                                                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                        \
    scratch_5 = in13;                                                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                        \
    scratch_6 = in14;                                                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                        \
    GF_MUL22( in11, in15, 1, 22, 1, 23 );                                                                                                                                                                            \
    scratch_3 = in11;                                                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                        \
    GF_MUL22( in08, in09, 9, 8, 1, 1 );                                                                                                                                                                              \
    in11 = GF_ADD( GF_MUL( in09, 1 ), in11 );                                                                                                                                                                        \
    GF_MUL22( in10, in11, 1, 10, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in08, in10, 29, 28, 1, 1 );                                                                                                                                                                            \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_3, 28 ), in09 );                                                                                                                                                                  \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                                                                                                        \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                                                                                                        \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                                                                                                        \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                        \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                                                                                                                  \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                                                                                                                                  \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                                                                                              \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                        \
    in03 = GF_ADD( GF_MUL( scratch_11, 0 ), in03 );                                                                                                                                                                  \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                        \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                  \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                        \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                        \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                        \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                        \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                        \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                        \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                        \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                        \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                        \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                        \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                        \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                  \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                        \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                  \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                        \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                  \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                        \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                  \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                        \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                  \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                        \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                  \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                  \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_12( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28    , \
    in29, in30, in31)                                                                                                                                                                                                \
  do {                                                                                                                                                                                                               \
    gf_t scratch_12, scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27;             \
    gf_t scratch_4, scratch_5, scratch_6, scratch_7;                                                                                                                                                                 \
    scratch_16 = in16;                                                                                                                                                                                               \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                        \
    scratch_17 = in17;                                                                                                                                                                                               \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                        \
    scratch_18 = in18;                                                                                                                                                                                               \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                        \
    scratch_19 = in19;                                                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                        \
    scratch_20 = in20;                                                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                        \
    scratch_21 = in21;                                                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                        \
    scratch_22 = in22;                                                                                                                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                        \
    scratch_23 = in23;                                                                                                                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                        \
    scratch_24 = in24;                                                                                                                                                                                               \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                        \
    scratch_25 = in25;                                                                                                                                                                                               \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                        \
    scratch_26 = in26;                                                                                                                                                                                               \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                        \
    scratch_27 = in27;                                                                                                                                                                                               \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                        \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                              \
    scratch_12 = in12;                                                                                                                                                                                               \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                        \
    scratch_13 = in13;                                                                                                                                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                        \
    scratch_14 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                        \
    scratch_15 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                                \
    in12 = GF_ADD( GF_MUL( in04, 1 ), in12 );                                                                                                                                                                        \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                        \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                        \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                        \
    scratch_4 = in12;                                                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                        \
    scratch_5 = in13;                                                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                        \
    scratch_6 = in14;                                                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                        \
    scratch_7 = in15;                                                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                                                                                                                                        \
    in12 = GF_ADD( GF_MUL( in08, 1 ), in12 );                                                                                                                                                                        \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                                                                                                        \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                                                                                                                        \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_FFT( 4, 12, in12, in13, in14, in15 );                                                                                                                                                        \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                        \
    in08 = GF_ADD( GF_MUL( scratch_4, 22 ), in08 );                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                                                                                                                  \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                                                                                                                                  \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                        \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                                                                                                                                  \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                                                                                              \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                                                                                              \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                        \
    in04 = GF_ADD( GF_MUL( scratch_12, 0 ), in04 );                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                  \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                        \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                        \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                        \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                        \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                        \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                        \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                        \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                        \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                        \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                        \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                        \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                        \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                  \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                        \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                  \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                        \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                  \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                        \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                  \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                        \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                  \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                        \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                  \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                  \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                        \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                  \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_13( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_13, scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27;             \
    gf_t scratch_28, scratch_5, scratch_6, scratch_7;                                                                                                                                                               \
    scratch_16 = in16;                                                                                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    scratch_25 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                       \
    scratch_26 = in26;                                                                                                                                                                                              \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                       \
    scratch_27 = in27;                                                                                                                                                                                              \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                       \
    scratch_28 = in28;                                                                                                                                                                                              \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                       \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                             \
    scratch_13 = in13;                                                                                                                                                                                              \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    scratch_14 = in14;                                                                                                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_15 = in15;                                                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                               \
    in13 = GF_ADD( GF_MUL( in05, 1 ), in13 );                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                       \
    scratch_5 = in13;                                                                                                                                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    scratch_6 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_7 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( in09, 1 ), in13 );                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                                                                                                                                       \
    scratch_2 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    GF_MUL22( in13, in15, 1, 26, 1, 27 );                                                                                                                                                                           \
    GF_MUL22( in12, in13, 1, 12, 1, 1 );                                                                                                                                                                            \
    in14 = GF_ADD( GF_MUL( in12, 1 ), in14 );                                                                                                                                                                       \
    GF_MUL22( in14, in15, 1, 14, 1, 15 );                                                                                                                                                                           \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_2, 26 ), in12 );                                                                                                                                                                 \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                                                                                                                                           \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_5, 22 ), in09 );                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                                                                                                                                 \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                                                                                             \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_13, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                       \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                       \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                       \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                       \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                              \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                       \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_14( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_14, scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28;             \
    gf_t scratch_29, scratch_3, scratch_6, scratch_7;                                                                                                                                                               \
    scratch_16 = in16;                                                                                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    scratch_25 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                       \
    scratch_26 = in26;                                                                                                                                                                                              \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                       \
    scratch_27 = in27;                                                                                                                                                                                              \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                       \
    scratch_28 = in28;                                                                                                                                                                                              \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                       \
    scratch_29 = in29;                                                                                                                                                                                              \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                       \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                             \
    scratch_14 = in14;                                                                                                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_15 = in15;                                                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                               \
    in14 = GF_ADD( GF_MUL( in06, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                       \
    scratch_6 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_7 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( in10, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                                                                                                                                       \
    scratch_2 = in14;                                                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    scratch_3 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    GF_MUL22( in12, in13, 13, 12, 1, 1 );                                                                                                                                                                           \
    in14 = GF_ADD( GF_MUL( in12, 1 ), in14 );                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in13, 1 ), in15 );                                                                                                                                                                       \
    GF_MUL22( in14, in15, 1, 14, 1, 15 );                                                                                                                                                                           \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_2, 26 ), in12 );                                                                                                                                                                 \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( scratch_3, 26 ), in13 );                                                                                                                                                                 \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in09, in13, 23, 22, 1, 1 );                                                                                                                                                                           \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_6, 22 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                                                                                                                                 \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                                                                                             \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_14, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                       \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                       \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                       \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                       \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                       \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                              \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                       \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                 \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_15( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_15, scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3;             \
    gf_t scratch_30, scratch_7;                                                                                                                                                                                     \
    scratch_16 = in16;                                                                                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    scratch_25 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                       \
    scratch_26 = in26;                                                                                                                                                                                              \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                       \
    scratch_27 = in27;                                                                                                                                                                                              \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                       \
    scratch_28 = in28;                                                                                                                                                                                              \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                       \
    scratch_29 = in29;                                                                                                                                                                                              \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                       \
    scratch_30 = in30;                                                                                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                       \
    GF_MUL22( in15, in31, 1, 0, 1, 1 );                                                                                                                                                                             \
    scratch_15 = in15;                                                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 8, 0, in00, in01, in02, in03, in04, in05, in06, in07 );                                                                                                                               \
    in15 = GF_ADD( GF_MUL( in07, 1 ), in15 );                                                                                                                                                                       \
    scratch_7 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 4, 8, in08, in09, in10, in11 );                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( in11, 1 ), in15 );                                                                                                                                                                       \
    scratch_3 = in15;                                                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    GF_MUL22( in12, in13, 13, 12, 1, 1 );                                                                                                                                                                           \
    in15 = GF_ADD( GF_MUL( in13, 1 ), in15 );                                                                                                                                                                       \
    GF_MUL22( in14, in15, 1, 14, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in12, in14, 27, 26, 1, 1 );                                                                                                                                                                           \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( scratch_3, 26 ), in13 );                                                                                                                                                                 \
    GF_MUL22( in08, in12, 23, 22, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in09, in13, 23, 22, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in10, in14, 23, 22, 1, 1 );                                                                                                                                                                           \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_7, 22 ), in11 );                                                                                                                                                                 \
    GF_MUL22( in00, in08, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in01, in09, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in02, in10, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in03, in11, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in04, in12, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in05, in13, 1, 0, 1, 1 );                                                                                                                                                                             \
    GF_MUL22( in06, in14, 1, 0, 1, 1 );                                                                                                                                                                             \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_15, 0 ), in07 );                                                                                                                                                                 \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                       \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                       \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                       \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                       \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                       \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                       \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                              \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                       \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                 \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                 \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                 \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_16( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28    , \
    in29, in30, in31)                                                                                                                                                                                                \
  do {                                                                                                                                                                                                               \
    gf_t scratch_16, scratch_17, scratch_18, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31;             \
    scratch_16 = in16;                                                                                                                                                                                               \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                        \
    scratch_17 = in17;                                                                                                                                                                                               \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                        \
    scratch_18 = in18;                                                                                                                                                                                               \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                        \
    scratch_19 = in19;                                                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                        \
    scratch_20 = in20;                                                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                        \
    scratch_21 = in21;                                                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                        \
    scratch_22 = in22;                                                                                                                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                        \
    scratch_23 = in23;                                                                                                                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                        \
    scratch_24 = in24;                                                                                                                                                                                               \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                        \
    scratch_25 = in25;                                                                                                                                                                                               \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                        \
    scratch_26 = in26;                                                                                                                                                                                               \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                        \
    scratch_27 = in27;                                                                                                                                                                                               \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                        \
    scratch_28 = in28;                                                                                                                                                                                               \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                        \
    scratch_29 = in29;                                                                                                                                                                                               \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                        \
    scratch_30 = in30;                                                                                                                                                                                               \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                        \
    scratch_31 = in31;                                                                                                                                                                                               \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                               \
    in16 = GF_ADD( GF_MUL( in00, 1 ), in16 );                                                                                                                                                                        \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                        \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                        \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                        \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                        \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                        \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                        \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                        \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                        \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                        \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                        \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                        \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                        \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                        \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                        \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                        \
    FD_REEDSOL_GENERATE_FFT( 16, 16, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                               \
    in00 = GF_MUL( in00, 1 );                                                                                                                                                                                        \
    in00 = GF_ADD( GF_MUL( scratch_16, 0 ), in00 );                                                                                                                                                                  \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                        \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                  \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                        \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                  \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                        \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                  \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                        \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                  \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                        \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                  \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                        \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                  \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                        \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                  \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                        \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                  \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                        \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                  \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                        \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                  \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                        \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                  \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                        \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                  \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                        \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                  \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                        \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                  \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                        \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                  \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_17( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28   , \
    in29, in30, in31)                                                                                                                                                                                               \
  do {                                                                                                                                                                                                              \
    gf_t scratch_17, scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31;             \
    gf_t scratch_4, scratch_8;                                                                                                                                                                                      \
    scratch_17 = in17;                                                                                                                                                                                              \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                       \
    scratch_18 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    scratch_19 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                       \
    scratch_20 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    scratch_21 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                       \
    scratch_22 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                       \
    scratch_23 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                       \
    scratch_24 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    scratch_25 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                       \
    scratch_26 = in26;                                                                                                                                                                                              \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                       \
    scratch_27 = in27;                                                                                                                                                                                              \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                       \
    scratch_28 = in28;                                                                                                                                                                                              \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                       \
    scratch_29 = in29;                                                                                                                                                                                              \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                       \
    scratch_30 = in30;                                                                                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                       \
    scratch_31 = in31;                                                                                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                              \
    in17 = GF_ADD( GF_MUL( in01, 1 ), in17 );                                                                                                                                                                       \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                       \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                       \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                       \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                       \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                       \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                       \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                       \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                       \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                       \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                       \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                       \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                       \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                       \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                       \
    scratch_8 = in24;                                                                                                                                                                                               \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                       \
    GF_MUL22( in17, in25, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in18, in26, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in19, in27, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in20, in28, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in21, in29, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                           \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                           \
    scratch_4 = in20;                                                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                       \
    GF_MUL22( in17, in21, 1, 97, 1, 96 );                                                                                                                                                                           \
    GF_MUL22( in18, in22, 1, 97, 1, 96 );                                                                                                                                                                           \
    GF_MUL22( in19, in23, 1, 97, 1, 96 );                                                                                                                                                                           \
    scratch_2 = in18;                                                                                                                                                                                               \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                       \
    GF_MUL22( in17, in19, 1, 120, 1, 121 );                                                                                                                                                                         \
    GF_MUL22( in16, in17, 1, 16, 1, 1 );                                                                                                                                                                            \
    in18 = GF_ADD( GF_MUL( in16, 1 ), in18 );                                                                                                                                                                       \
    GF_MUL22( in18, in19, 1, 18, 1, 19 );                                                                                                                                                                           \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    in16 = GF_ADD( GF_MUL( scratch_2, 120 ), in16 );                                                                                                                                                                \
    in20 = GF_ADD( GF_MUL( in16, 1 ), in20 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 4, 20, in20, in21, in22, in23 );                                                                                                                                                       \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    in16 = GF_ADD( GF_MUL( scratch_4, 97 ), in16 );                                                                                                                                                                 \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                       \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                               \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                       \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                 \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                             \
    in01 = GF_MUL( in01, 1 );                                                                                                                                                                                       \
    in01 = GF_ADD( GF_MUL( scratch_17, 0 ), in01 );                                                                                                                                                                 \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                       \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                 \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                       \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                 \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                       \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                 \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                       \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                 \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                       \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                 \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                       \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                 \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                       \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                 \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                       \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                 \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                       \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                 \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                       \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                 \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                       \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                 \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                       \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                 \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                       \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                 \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                       \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                 \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_18( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_18, scratch_19, scratch_2, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31;             \
    gf_t scratch_4, scratch_5, scratch_8, scratch_9;                                                                                                                                                               \
    scratch_18 = in18;                                                                                                                                                                                             \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    scratch_19 = in19;                                                                                                                                                                                             \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    scratch_20 = in20;                                                                                                                                                                                             \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_21 = in21;                                                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in18 = GF_ADD( GF_MUL( in02, 1 ), in18 );                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    GF_MUL22( in18, in26, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in19, in27, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in20, in28, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in21, in29, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_4 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_5 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    GF_MUL22( in18, in22, 1, 97, 1, 96 );                                                                                                                                                                          \
    GF_MUL22( in19, in23, 1, 97, 1, 96 );                                                                                                                                                                          \
    scratch_2 = in18;                                                                                                                                                                                              \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    scratch_3 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    GF_MUL22( in16, in17, 17, 16, 1, 1 );                                                                                                                                                                          \
    in18 = GF_ADD( GF_MUL( in16, 1 ), in18 );                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( in17, 1 ), in19 );                                                                                                                                                                      \
    GF_MUL22( in18, in19, 1, 18, 1, 19 );                                                                                                                                                                          \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_2, 120 ), in16 );                                                                                                                                                               \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_3, 120 ), in17 );                                                                                                                                                               \
    in20 = GF_ADD( GF_MUL( in16, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in17, 1 ), in21 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 20, in20, in21, in22, in23 );                                                                                                                                                      \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_4, 97 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_5, 97 ), in17 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    in02 = GF_MUL( in02, 1 );                                                                                                                                                                                      \
    in02 = GF_ADD( GF_MUL( scratch_18, 0 ), in02 );                                                                                                                                                                \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                      \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_19( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_19, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31, scratch_4;             \
    gf_t scratch_5, scratch_6, scratch_8, scratch_9;                                                                                                                                                               \
    scratch_19 = in19;                                                                                                                                                                                             \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    scratch_20 = in20;                                                                                                                                                                                             \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_21 = in21;                                                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in19 = GF_ADD( GF_MUL( in03, 1 ), in19 );                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    GF_MUL22( in19, in27, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in20, in28, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in21, in29, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_4 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_5 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_6 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    GF_MUL22( in19, in23, 1, 97, 1, 96 );                                                                                                                                                                          \
    scratch_3 = in19;                                                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    GF_MUL22( in16, in17, 17, 16, 1, 1 );                                                                                                                                                                          \
    in19 = GF_ADD( GF_MUL( in17, 1 ), in19 );                                                                                                                                                                      \
    GF_MUL22( in18, in19, 1, 18, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in16, in18, 121, 120, 1, 1 );                                                                                                                                                                        \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_3, 120 ), in17 );                                                                                                                                                               \
    in20 = GF_ADD( GF_MUL( in16, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in17, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in18, 1 ), in22 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 20, in20, in21, in22, in23 );                                                                                                                                                      \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_4, 97 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_5, 97 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_6, 97 ), in18 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    in03 = GF_MUL( in03, 1 );                                                                                                                                                                                      \
    in03 = GF_ADD( GF_MUL( scratch_19, 0 ), in03 );                                                                                                                                                                \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_20( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_20, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31, scratch_4, scratch_5;             \
    gf_t scratch_6, scratch_7, scratch_8, scratch_9;                                                                                                                                                               \
    scratch_20 = in20;                                                                                                                                                                                             \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_21 = in21;                                                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in20 = GF_ADD( GF_MUL( in04, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_11 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    GF_MUL22( in20, in28, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in21, in29, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_4 = in20;                                                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    scratch_5 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_6 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_7 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 16, in16, in17, in18, in19 );                                                                                                                                                     \
    in20 = GF_ADD( GF_MUL( in16, 1 ), in20 );                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( in17, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in18, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in19, 1 ), in23 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 4, 20, in20, in21, in22, in23 );                                                                                                                                                      \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_4, 97 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_5, 97 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_6, 97 ), in18 );                                                                                                                                                                \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_7, 97 ), in19 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                            \
    in04 = GF_MUL( in04, 1 );                                                                                                                                                                                      \
    in04 = GF_ADD( GF_MUL( scratch_20, 0 ), in04 );                                                                                                                                                                \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_21( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_2, scratch_21, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31, scratch_5;             \
    gf_t scratch_6, scratch_7, scratch_8, scratch_9;                                                                                                                                                               \
    scratch_21 = in21;                                                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in21 = GF_ADD( GF_MUL( in05, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_11 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_12 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    GF_MUL22( in21, in29, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_5 = in21;                                                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    scratch_6 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_7 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 16, in16, in17, in18, in19 );                                                                                                                                                     \
    in21 = GF_ADD( GF_MUL( in17, 1 ), in21 );                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( in18, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in19, 1 ), in23 );                                                                                                                                                                      \
    scratch_2 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    GF_MUL22( in21, in23, 1, 126, 1, 127 );                                                                                                                                                                        \
    GF_MUL22( in20, in21, 1, 20, 1, 1 );                                                                                                                                                                           \
    in22 = GF_ADD( GF_MUL( in20, 1 ), in22 );                                                                                                                                                                      \
    GF_MUL22( in22, in23, 1, 22, 1, 23 );                                                                                                                                                                          \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_2, 126 ), in20 );                                                                                                                                                               \
    GF_MUL22( in16, in20, 96, 97, 1, 1 );                                                                                                                                                                          \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_5, 97 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_6, 97 ), in18 );                                                                                                                                                                \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_7, 97 ), in19 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                            \
    in05 = GF_MUL( in05, 1 );                                                                                                                                                                                      \
    in05 = GF_ADD( GF_MUL( scratch_21, 0 ), in05 );                                                                                                                                                                \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_22( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_2, scratch_22, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31;             \
    gf_t scratch_6, scratch_7, scratch_8, scratch_9;                                                                                                                                                               \
    scratch_22 = in22;                                                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in22 = GF_ADD( GF_MUL( in06, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_11 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_12 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_13 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    GF_MUL22( in22, in30, 1, 11, 1, 10 );                                                                                                                                                                          \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_6 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_7 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 16, in16, in17, in18, in19 );                                                                                                                                                     \
    in22 = GF_ADD( GF_MUL( in18, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in19, 1 ), in23 );                                                                                                                                                                      \
    scratch_2 = in22;                                                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    scratch_3 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    GF_MUL22( in20, in21, 21, 20, 1, 1 );                                                                                                                                                                          \
    in22 = GF_ADD( GF_MUL( in20, 1 ), in22 );                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( in21, 1 ), in23 );                                                                                                                                                                      \
    GF_MUL22( in22, in23, 1, 22, 1, 23 );                                                                                                                                                                          \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_2, 126 ), in20 );                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_3, 126 ), in21 );                                                                                                                                                               \
    GF_MUL22( in16, in20, 96, 97, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in17, in21, 96, 97, 1, 1 );                                                                                                                                                                          \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_6, 97 ), in18 );                                                                                                                                                                \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_7, 97 ), in19 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                                            \
    in06 = GF_MUL( in06, 1 );                                                                                                                                                                                      \
    in06 = GF_ADD( GF_MUL( scratch_22, 0 ), in06 );                                                                                                                                                                \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_23( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_23, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31, scratch_7;             \
    gf_t scratch_8, scratch_9;                                                                                                                                                                                     \
    scratch_23 = in23;                                                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in23 = GF_ADD( GF_MUL( in07, 1 ), in23 );                                                                                                                                                                      \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_11 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_12 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_13 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_14 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    GF_MUL22( in23, in31, 1, 11, 1, 10 );                                                                                                                                                                          \
    scratch_7 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 16, in16, in17, in18, in19 );                                                                                                                                                     \
    in23 = GF_ADD( GF_MUL( in19, 1 ), in23 );                                                                                                                                                                      \
    scratch_3 = in23;                                                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    GF_MUL22( in20, in21, 21, 20, 1, 1 );                                                                                                                                                                          \
    in23 = GF_ADD( GF_MUL( in21, 1 ), in23 );                                                                                                                                                                      \
    GF_MUL22( in22, in23, 1, 22, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in20, in22, 127, 126, 1, 1 );                                                                                                                                                                        \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_3, 126 ), in21 );                                                                                                                                                               \
    GF_MUL22( in16, in20, 96, 97, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in17, in21, 96, 97, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in18, in22, 96, 97, 1, 1 );                                                                                                                                                                          \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_7, 97 ), in19 );                                                                                                                                                                \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                                            \
    in07 = GF_MUL( in07, 1 );                                                                                                                                                                                      \
    in07 = GF_ADD( GF_MUL( scratch_23, 0 ), in07 );                                                                                                                                                                \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_24( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28  , \
    in29, in30, in31)                                                                                                                                                                                              \
  do {                                                                                                                                                                                                             \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_24, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31, scratch_8, scratch_9;             \
    scratch_24 = in24;                                                                                                                                                                                             \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_25 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_26 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_27 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_28 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_29 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_30 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_31 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                             \
    in24 = GF_ADD( GF_MUL( in08, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                      \
    scratch_8 = in24;                                                                                                                                                                                              \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                      \
    scratch_9 = in25;                                                                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                      \
    scratch_10 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                      \
    scratch_11 = in27;                                                                                                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                      \
    scratch_12 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                      \
    scratch_13 = in29;                                                                                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                      \
    scratch_14 = in30;                                                                                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                      \
    scratch_15 = in31;                                                                                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                                                                                             \
    in24 = GF_ADD( GF_MUL( in16, 1 ), in24 );                                                                                                                                                                      \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                      \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                      \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                      \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                      \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                                                      \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                                                                      \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                                                                                      \
    FD_REEDSOL_GENERATE_FFT( 8, 24, in24, in25, in26, in27, in28, in29, in30, in31 );                                                                                                                              \
    in16 = GF_MUL( in16, 1 );                                                                                                                                                                                      \
    in16 = GF_ADD( GF_MUL( scratch_8, 11 ), in16 );                                                                                                                                                                \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                      \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                                \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                      \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                               \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                      \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                               \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                      \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                               \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                      \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                      \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                                            \
    in08 = GF_MUL( in08, 1 );                                                                                                                                                                                      \
    in08 = GF_ADD( GF_MUL( scratch_24, 0 ), in08 );                                                                                                                                                                \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                      \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                                \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                      \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                                \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                      \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                                \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                      \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                                \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_25( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28 , \
    in29, in30, in31)                                                                                                                                                                                             \
  do {                                                                                                                                                                                                            \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_2, scratch_25, scratch_26, scratch_27, scratch_28, scratch_29, scratch_30, scratch_31, scratch_4, scratch_9;             \
    scratch_25 = in25;                                                                                                                                                                                            \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                     \
    scratch_26 = in26;                                                                                                                                                                                            \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                     \
    scratch_27 = in27;                                                                                                                                                                                            \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                     \
    scratch_28 = in28;                                                                                                                                                                                            \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                     \
    scratch_29 = in29;                                                                                                                                                                                            \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                     \
    scratch_30 = in30;                                                                                                                                                                                            \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                     \
    scratch_31 = in31;                                                                                                                                                                                            \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                            \
    in25 = GF_ADD( GF_MUL( in09, 1 ), in25 );                                                                                                                                                                     \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                     \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                     \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                     \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                     \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                     \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                     \
    scratch_9 = in25;                                                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                     \
    scratch_10 = in26;                                                                                                                                                                                            \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                     \
    scratch_11 = in27;                                                                                                                                                                                            \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                     \
    scratch_12 = in28;                                                                                                                                                                                            \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                     \
    scratch_13 = in29;                                                                                                                                                                                            \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                     \
    scratch_14 = in30;                                                                                                                                                                                            \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                     \
    scratch_15 = in31;                                                                                                                                                                                            \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                     \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                                                                                            \
    in25 = GF_ADD( GF_MUL( in17, 1 ), in25 );                                                                                                                                                                     \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                     \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                     \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                     \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                                                     \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                                                                     \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                                                                                     \
    scratch_4 = in28;                                                                                                                                                                                             \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                     \
    GF_MUL22( in25, in29, 1, 119, 1, 118 );                                                                                                                                                                       \
    GF_MUL22( in26, in30, 1, 119, 1, 118 );                                                                                                                                                                       \
    GF_MUL22( in27, in31, 1, 119, 1, 118 );                                                                                                                                                                       \
    scratch_2 = in26;                                                                                                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                     \
    GF_MUL22( in25, in27, 1, 100, 1, 101 );                                                                                                                                                                       \
    GF_MUL22( in24, in25, 1, 24, 1, 1 );                                                                                                                                                                          \
    in26 = GF_ADD( GF_MUL( in24, 1 ), in26 );                                                                                                                                                                     \
    GF_MUL22( in26, in27, 1, 26, 1, 27 );                                                                                                                                                                         \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                     \
    in24 = GF_ADD( GF_MUL( scratch_2, 100 ), in24 );                                                                                                                                                              \
    in28 = GF_ADD( GF_MUL( in24, 1 ), in28 );                                                                                                                                                                     \
    FD_REEDSOL_GENERATE_FFT( 4, 28, in28, in29, in30, in31 );                                                                                                                                                     \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                     \
    in24 = GF_ADD( GF_MUL( scratch_4, 119 ), in24 );                                                                                                                                                              \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                                                                                         \
    in17 = GF_MUL( in17, 1 );                                                                                                                                                                                     \
    in17 = GF_ADD( GF_MUL( scratch_9, 11 ), in17 );                                                                                                                                                               \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                     \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                              \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                     \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                              \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                     \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                              \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                     \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                                              \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                     \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                                                                              \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                     \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                                                                                              \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                                           \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                                           \
    in09 = GF_MUL( in09, 1 );                                                                                                                                                                                     \
    in09 = GF_ADD( GF_MUL( scratch_25, 0 ), in09 );                                                                                                                                                               \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                     \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                               \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                     \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                               \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                     \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                               \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                     \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                               \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                     \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                               \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                     \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                               \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_26( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, \
    in29, in30, in31)                                                                                                                                                                                            \
  do {                                                                                                                                                                                                           \
    gf_t scratch_10, scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_2, scratch_26, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31, scratch_4, scratch_5;             \
    scratch_26 = in26;                                                                                                                                                                                           \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                    \
    scratch_27 = in27;                                                                                                                                                                                           \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                    \
    scratch_28 = in28;                                                                                                                                                                                           \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                    \
    scratch_29 = in29;                                                                                                                                                                                           \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                    \
    scratch_30 = in30;                                                                                                                                                                                           \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                    \
    scratch_31 = in31;                                                                                                                                                                                           \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                                           \
    in26 = GF_ADD( GF_MUL( in10, 1 ), in26 );                                                                                                                                                                    \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                                                    \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                                                    \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                                                    \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                                                    \
    scratch_10 = in26;                                                                                                                                                                                           \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                    \
    scratch_11 = in27;                                                                                                                                                                                           \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                    \
    scratch_12 = in28;                                                                                                                                                                                           \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                    \
    scratch_13 = in29;                                                                                                                                                                                           \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                    \
    scratch_14 = in30;                                                                                                                                                                                           \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                                                    \
    scratch_15 = in31;                                                                                                                                                                                           \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                                                                                           \
    in26 = GF_ADD( GF_MUL( in18, 1 ), in26 );                                                                                                                                                                    \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                                                    \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                                                    \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                                                                    \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                                                                                    \
    scratch_4 = in28;                                                                                                                                                                                            \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                                                    \
    scratch_5 = in29;                                                                                                                                                                                            \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                                                    \
    GF_MUL22( in26, in30, 1, 119, 1, 118 );                                                                                                                                                                      \
    GF_MUL22( in27, in31, 1, 119, 1, 118 );                                                                                                                                                                      \
    scratch_2 = in26;                                                                                                                                                                                            \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                                                    \
    scratch_3 = in27;                                                                                                                                                                                            \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                                                    \
    GF_MUL22( in24, in25, 25, 24, 1, 1 );                                                                                                                                                                        \
    in26 = GF_ADD( GF_MUL( in24, 1 ), in26 );                                                                                                                                                                    \
    in27 = GF_ADD( GF_MUL( in25, 1 ), in27 );                                                                                                                                                                    \
    GF_MUL22( in26, in27, 1, 26, 1, 27 );                                                                                                                                                                        \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                    \
    in24 = GF_ADD( GF_MUL( scratch_2, 100 ), in24 );                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                    \
    in25 = GF_ADD( GF_MUL( scratch_3, 100 ), in25 );                                                                                                                                                             \
    in28 = GF_ADD( GF_MUL( in24, 1 ), in28 );                                                                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in25, 1 ), in29 );                                                                                                                                                                    \
    FD_REEDSOL_GENERATE_FFT( 4, 28, in28, in29, in30, in31 );                                                                                                                                                    \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                                                    \
    in24 = GF_ADD( GF_MUL( scratch_4, 119 ), in24 );                                                                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                                                    \
    in25 = GF_ADD( GF_MUL( scratch_5, 119 ), in25 );                                                                                                                                                             \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                                                                                        \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                                                                                        \
    in18 = GF_MUL( in18, 1 );                                                                                                                                                                                    \
    in18 = GF_ADD( GF_MUL( scratch_10, 11 ), in18 );                                                                                                                                                             \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                                                    \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                                             \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                                                    \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                                                    \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                                                    \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                                                    \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                                                                                             \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                                          \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                                          \
    in10 = GF_MUL( in10, 1 );                                                                                                                                                                                    \
    in10 = GF_ADD( GF_MUL( scratch_26, 0 ), in10 );                                                                                                                                                              \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                                                    \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                                              \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                                                    \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                                              \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                                                    \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                                                    \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                                                    \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                                              \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_27( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, in21, in22, in23, in24, \
    in25, in26, in27, in28, in29, in30, in31)                                                                                                                                            \
  do {                                                                                                                                                                                   \
    gf_t scratch_11, scratch_12, scratch_13, scratch_14, scratch_15, scratch_27, scratch_28, scratch_29, scratch_3, scratch_30, scratch_31, scratch_4, scratch_5, scratch_6;             \
    scratch_27 = in27;                                                                                                                                                                   \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                            \
    scratch_28 = in28;                                                                                                                                                                   \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                            \
    scratch_29 = in29;                                                                                                                                                                   \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                            \
    scratch_30 = in30;                                                                                                                                                                   \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                            \
    scratch_31 = in31;                                                                                                                                                                   \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                            \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                                                   \
    in27 = GF_ADD( GF_MUL( in11, 1 ), in27 );                                                                                                                                            \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                                            \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                                            \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                                            \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                                            \
    scratch_11 = in27;                                                                                                                                                                   \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                            \
    scratch_12 = in28;                                                                                                                                                                   \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                            \
    scratch_13 = in29;                                                                                                                                                                   \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                            \
    scratch_14 = in30;                                                                                                                                                                   \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                            \
    scratch_15 = in31;                                                                                                                                                                   \
    in31 = GF_MUL( in31, 1 );                                                                                                                                                            \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                                                                   \
    in27 = GF_ADD( GF_MUL( in19, 1 ), in27 );                                                                                                                                            \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                                            \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                                            \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                                            \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                                                            \
    scratch_4 = in28;                                                                                                                                                                    \
    in28 = GF_MUL( in28, 1 );                                                                                                                                                            \
    scratch_5 = in29;                                                                                                                                                                    \
    in29 = GF_MUL( in29, 1 );                                                                                                                                                            \
    scratch_6 = in30;                                                                                                                                                                    \
    in30 = GF_MUL( in30, 1 );                                                                                                                                                            \
    GF_MUL22( in27, in31, 1, 119, 1, 118 );                                                                                                                                              \
    scratch_3 = in27;                                                                                                                                                                    \
    in27 = GF_MUL( in27, 1 );                                                                                                                                                            \
    GF_MUL22( in24, in25, 25, 24, 1, 1 );                                                                                                                                                \
    in27 = GF_ADD( GF_MUL( in25, 1 ), in27 );                                                                                                                                            \
    GF_MUL22( in26, in27, 1, 26, 1, 1 );                                                                                                                                                 \
    GF_MUL22( in24, in26, 101, 100, 1, 1 );                                                                                                                                              \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                            \
    in25 = GF_ADD( GF_MUL( scratch_3, 100 ), in25 );                                                                                                                                     \
    in28 = GF_ADD( GF_MUL( in24, 1 ), in28 );                                                                                                                                            \
    in29 = GF_ADD( GF_MUL( in25, 1 ), in29 );                                                                                                                                            \
    in30 = GF_ADD( GF_MUL( in26, 1 ), in30 );                                                                                                                                            \
    FD_REEDSOL_GENERATE_FFT( 4, 28, in28, in29, in30, in31 );                                                                                                                            \
    in24 = GF_MUL( in24, 1 );                                                                                                                                                            \
    in24 = GF_ADD( GF_MUL( scratch_4, 119 ), in24 );                                                                                                                                     \
    in25 = GF_MUL( in25, 1 );                                                                                                                                                            \
    in25 = GF_ADD( GF_MUL( scratch_5, 119 ), in25 );                                                                                                                                     \
    in26 = GF_MUL( in26, 1 );                                                                                                                                                            \
    in26 = GF_ADD( GF_MUL( scratch_6, 119 ), in26 );                                                                                                                                     \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                                                                \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                                                                \
    GF_MUL22( in18, in26, 10, 11, 1, 1 );                                                                                                                                                \
    in19 = GF_MUL( in19, 1 );                                                                                                                                                            \
    in19 = GF_ADD( GF_MUL( scratch_11, 11 ), in19 );                                                                                                                                     \
    in20 = GF_MUL( in20, 1 );                                                                                                                                                            \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                                                     \
    in21 = GF_MUL( in21, 1 );                                                                                                                                                            \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                                                     \
    in22 = GF_MUL( in22, 1 );                                                                                                                                                            \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                                                     \
    in23 = GF_MUL( in23, 1 );                                                                                                                                                            \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                                                                     \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                                                  \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                                                  \
    in11 = GF_MUL( in11, 1 );                                                                                                                                                            \
    in11 = GF_ADD( GF_MUL( scratch_27, 0 ), in11 );                                                                                                                                      \
    in12 = GF_MUL( in12, 1 );                                                                                                                                                            \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                                                      \
    in13 = GF_MUL( in13, 1 );                                                                                                                                                            \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                                                      \
    in14 = GF_MUL( in14, 1 );                                                                                                                                                            \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                                                      \
    in15 = GF_MUL( in15, 1 );                                                                                                                                                            \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                                                      \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_28( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, in20, \
    in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                                                            \
  do {                                                                                                                                                           \
    gf_t scratch_12, scratch_13, scratch_14, scratch_15, scratch_28, scratch_29, scratch_30, scratch_31, scratch_4, scratch_5, scratch_6, scratch_7;             \
    scratch_28 = in28;                                                                                                                                           \
    in28 = GF_MUL( in28, 1 );                                                                                                                                    \
    scratch_29 = in29;                                                                                                                                           \
    in29 = GF_MUL( in29, 1 );                                                                                                                                    \
    scratch_30 = in30;                                                                                                                                           \
    in30 = GF_MUL( in30, 1 );                                                                                                                                    \
    scratch_31 = in31;                                                                                                                                           \
    in31 = GF_MUL( in31, 1 );                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );                           \
    in28 = GF_ADD( GF_MUL( in12, 1 ), in28 );                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                                    \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                                    \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                                    \
    scratch_12 = in28;                                                                                                                                           \
    in28 = GF_MUL( in28, 1 );                                                                                                                                    \
    scratch_13 = in29;                                                                                                                                           \
    in29 = GF_MUL( in29, 1 );                                                                                                                                    \
    scratch_14 = in30;                                                                                                                                           \
    in30 = GF_MUL( in30, 1 );                                                                                                                                    \
    scratch_15 = in31;                                                                                                                                           \
    in31 = GF_MUL( in31, 1 );                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                                           \
    in28 = GF_ADD( GF_MUL( in20, 1 ), in28 );                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                                    \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                                    \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                                    \
    scratch_4 = in28;                                                                                                                                            \
    in28 = GF_MUL( in28, 1 );                                                                                                                                    \
    scratch_5 = in29;                                                                                                                                            \
    in29 = GF_MUL( in29, 1 );                                                                                                                                    \
    scratch_6 = in30;                                                                                                                                            \
    in30 = GF_MUL( in30, 1 );                                                                                                                                    \
    scratch_7 = in31;                                                                                                                                            \
    in31 = GF_MUL( in31, 1 );                                                                                                                                    \
    FD_REEDSOL_GENERATE_IFFT( 4, 24, in24, in25, in26, in27 );                                                                                                   \
    in28 = GF_ADD( GF_MUL( in24, 1 ), in28 );                                                                                                                    \
    in29 = GF_ADD( GF_MUL( in25, 1 ), in29 );                                                                                                                    \
    in30 = GF_ADD( GF_MUL( in26, 1 ), in30 );                                                                                                                    \
    in31 = GF_ADD( GF_MUL( in27, 1 ), in31 );                                                                                                                    \
    FD_REEDSOL_GENERATE_FFT( 4, 28, in28, in29, in30, in31 );                                                                                                    \
    in24 = GF_MUL( in24, 1 );                                                                                                                                    \
    in24 = GF_ADD( GF_MUL( scratch_4, 119 ), in24 );                                                                                                             \
    in25 = GF_MUL( in25, 1 );                                                                                                                                    \
    in25 = GF_ADD( GF_MUL( scratch_5, 119 ), in25 );                                                                                                             \
    in26 = GF_MUL( in26, 1 );                                                                                                                                    \
    in26 = GF_ADD( GF_MUL( scratch_6, 119 ), in26 );                                                                                                             \
    in27 = GF_MUL( in27, 1 );                                                                                                                                    \
    in27 = GF_ADD( GF_MUL( scratch_7, 119 ), in27 );                                                                                                             \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                                        \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                                        \
    GF_MUL22( in18, in26, 10, 11, 1, 1 );                                                                                                                        \
    GF_MUL22( in19, in27, 10, 11, 1, 1 );                                                                                                                        \
    in20 = GF_MUL( in20, 1 );                                                                                                                                    \
    in20 = GF_ADD( GF_MUL( scratch_12, 11 ), in20 );                                                                                                             \
    in21 = GF_MUL( in21, 1 );                                                                                                                                    \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                                             \
    in22 = GF_MUL( in22, 1 );                                                                                                                                    \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                                             \
    in23 = GF_MUL( in23, 1 );                                                                                                                                    \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                                             \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                                          \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                                          \
    in12 = GF_MUL( in12, 1 );                                                                                                                                    \
    in12 = GF_ADD( GF_MUL( scratch_28, 0 ), in12 );                                                                                                              \
    in13 = GF_MUL( in13, 1 );                                                                                                                                    \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                              \
    in14 = GF_MUL( in14, 1 );                                                                                                                                    \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                              \
    in15 = GF_MUL( in15, 1 );                                                                                                                                    \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                              \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_29( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17    , \
    in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                            \
  do {                                                                                                                                             \
    gf_t scratch_13, scratch_14, scratch_15, scratch_2, scratch_29, scratch_30, scratch_31, scratch_5, scratch_6, scratch_7;                       \
    scratch_29 = in29;                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                      \
    scratch_30 = in30;                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_31 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );             \
    in29 = GF_ADD( GF_MUL( in13, 1 ), in29 );                                                                                                      \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                      \
    scratch_13 = in29;                                                                                                                             \
    in29 = GF_MUL( in29, 1 );                                                                                                                      \
    scratch_14 = in30;                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_15 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                             \
    in29 = GF_ADD( GF_MUL( in21, 1 ), in29 );                                                                                                      \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                      \
    scratch_5 = in29;                                                                                                                              \
    in29 = GF_MUL( in29, 1 );                                                                                                                      \
    scratch_6 = in30;                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_7 = in31;                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 24, in24, in25, in26, in27 );                                                                                     \
    in29 = GF_ADD( GF_MUL( in25, 1 ), in29 );                                                                                                      \
    in30 = GF_ADD( GF_MUL( in26, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in27, 1 ), in31 );                                                                                                      \
    scratch_2 = in30;                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    GF_MUL22( in29, in31, 1, 98, 1, 99 );                                                                                                          \
    GF_MUL22( in28, in29, 1, 28, 1, 1 );                                                                                                           \
    in30 = GF_ADD( GF_MUL( in28, 1 ), in30 );                                                                                                      \
    GF_MUL22( in30, in31, 1, 30, 1, 31 );                                                                                                          \
    in28 = GF_MUL( in28, 1 );                                                                                                                      \
    in28 = GF_ADD( GF_MUL( scratch_2, 98 ), in28 );                                                                                                \
    GF_MUL22( in24, in28, 118, 119, 1, 1 );                                                                                                        \
    in25 = GF_MUL( in25, 1 );                                                                                                                      \
    in25 = GF_ADD( GF_MUL( scratch_5, 119 ), in25 );                                                                                               \
    in26 = GF_MUL( in26, 1 );                                                                                                                      \
    in26 = GF_ADD( GF_MUL( scratch_6, 119 ), in26 );                                                                                               \
    in27 = GF_MUL( in27, 1 );                                                                                                                      \
    in27 = GF_ADD( GF_MUL( scratch_7, 119 ), in27 );                                                                                               \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in18, in26, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in19, in27, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in20, in28, 10, 11, 1, 1 );                                                                                                          \
    in21 = GF_MUL( in21, 1 );                                                                                                                      \
    in21 = GF_ADD( GF_MUL( scratch_13, 11 ), in21 );                                                                                               \
    in22 = GF_MUL( in22, 1 );                                                                                                                      \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                      \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    in13 = GF_MUL( in13, 1 );                                                                                                                      \
    in13 = GF_ADD( GF_MUL( scratch_29, 0 ), in13 );                                                                                                \
    in14 = GF_MUL( in14, 1 );                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_30( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17    , \
    in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                            \
  do {                                                                                                                                             \
    gf_t scratch_14, scratch_15, scratch_2, scratch_3, scratch_30, scratch_31, scratch_6, scratch_7;                                               \
    scratch_30 = in30;                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_31 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );             \
    in30 = GF_ADD( GF_MUL( in14, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                      \
    scratch_14 = in30;                                                                                                                             \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_15 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                             \
    in30 = GF_ADD( GF_MUL( in22, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                      \
    scratch_6 = in30;                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_7 = in31;                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 24, in24, in25, in26, in27 );                                                                                     \
    in30 = GF_ADD( GF_MUL( in26, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in27, 1 ), in31 );                                                                                                      \
    scratch_2 = in30;                                                                                                                              \
    in30 = GF_MUL( in30, 1 );                                                                                                                      \
    scratch_3 = in31;                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    GF_MUL22( in28, in29, 29, 28, 1, 1 );                                                                                                          \
    in30 = GF_ADD( GF_MUL( in28, 1 ), in30 );                                                                                                      \
    in31 = GF_ADD( GF_MUL( in29, 1 ), in31 );                                                                                                      \
    GF_MUL22( in30, in31, 1, 30, 1, 31 );                                                                                                          \
    in28 = GF_MUL( in28, 1 );                                                                                                                      \
    in28 = GF_ADD( GF_MUL( scratch_2, 98 ), in28 );                                                                                                \
    in29 = GF_MUL( in29, 1 );                                                                                                                      \
    in29 = GF_ADD( GF_MUL( scratch_3, 98 ), in29 );                                                                                                \
    GF_MUL22( in24, in28, 118, 119, 1, 1 );                                                                                                        \
    GF_MUL22( in25, in29, 118, 119, 1, 1 );                                                                                                        \
    in26 = GF_MUL( in26, 1 );                                                                                                                      \
    in26 = GF_ADD( GF_MUL( scratch_6, 119 ), in26 );                                                                                               \
    in27 = GF_MUL( in27, 1 );                                                                                                                      \
    in27 = GF_ADD( GF_MUL( scratch_7, 119 ), in27 );                                                                                               \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in18, in26, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in19, in27, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in20, in28, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in21, in29, 10, 11, 1, 1 );                                                                                                          \
    in22 = GF_MUL( in22, 1 );                                                                                                                      \
    in22 = GF_ADD( GF_MUL( scratch_14, 11 ), in22 );                                                                                               \
    in23 = GF_MUL( in23, 1 );                                                                                                                      \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                            \
    in14 = GF_MUL( in14, 1 );                                                                                                                      \
    in14 = GF_ADD( GF_MUL( scratch_30, 0 ), in14 );                                                                                                \
    in15 = GF_MUL( in15, 1 );                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                \
  } while( 0 )



#define FD_REEDSOL_PPT_IMPL_32_31( in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15, in16, in17    , \
    in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31)                                                            \
  do {                                                                                                                                             \
    gf_t scratch_15, scratch_3, scratch_31, scratch_7;                                                                                             \
    scratch_31 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 16, 0, in00, in01, in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, in13, in14, in15 );             \
    in31 = GF_ADD( GF_MUL( in15, 1 ), in31 );                                                                                                      \
    scratch_15 = in31;                                                                                                                             \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 8, 16, in16, in17, in18, in19, in20, in21, in22, in23 );                                                             \
    in31 = GF_ADD( GF_MUL( in23, 1 ), in31 );                                                                                                      \
    scratch_7 = in31;                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    FD_REEDSOL_GENERATE_IFFT( 4, 24, in24, in25, in26, in27 );                                                                                     \
    in31 = GF_ADD( GF_MUL( in27, 1 ), in31 );                                                                                                      \
    scratch_3 = in31;                                                                                                                              \
    in31 = GF_MUL( in31, 1 );                                                                                                                      \
    GF_MUL22( in28, in29, 29, 28, 1, 1 );                                                                                                          \
    in31 = GF_ADD( GF_MUL( in29, 1 ), in31 );                                                                                                      \
    GF_MUL22( in30, in31, 1, 30, 1, 1 );                                                                                                           \
    GF_MUL22( in28, in30, 99, 98, 1, 1 );                                                                                                          \
    in29 = GF_MUL( in29, 1 );                                                                                                                      \
    in29 = GF_ADD( GF_MUL( scratch_3, 98 ), in29 );                                                                                                \
    GF_MUL22( in24, in28, 118, 119, 1, 1 );                                                                                                        \
    GF_MUL22( in25, in29, 118, 119, 1, 1 );                                                                                                        \
    GF_MUL22( in26, in30, 118, 119, 1, 1 );                                                                                                        \
    in27 = GF_MUL( in27, 1 );                                                                                                                      \
    in27 = GF_ADD( GF_MUL( scratch_7, 119 ), in27 );                                                                                               \
    GF_MUL22( in16, in24, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in17, in25, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in18, in26, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in19, in27, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in20, in28, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in21, in29, 10, 11, 1, 1 );                                                                                                          \
    GF_MUL22( in22, in30, 10, 11, 1, 1 );                                                                                                          \
    in23 = GF_MUL( in23, 1 );                                                                                                                      \
    in23 = GF_ADD( GF_MUL( scratch_15, 11 ), in23 );                                                                                               \
    GF_MUL22( in00, in16, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in01, in17, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in02, in18, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in03, in19, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in04, in20, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in05, in21, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in06, in22, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in07, in23, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in08, in24, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in09, in25, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in10, in26, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in11, in27, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in12, in28, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in13, in29, 1, 0, 1, 1 );                                                                                                            \
    GF_MUL22( in14, in30, 1, 0, 1, 1 );                                                                                                            \
    in15 = GF_MUL( in15, 1 );                                                                                                                      \
    in15 = GF_ADD( GF_MUL( scratch_31, 0 ), in15 );                                                                                                \
  } while( 0 )



#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h */
