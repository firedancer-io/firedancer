
/* Note: This file is auto generated. */
#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h

/* This file implements the FFT-like operator described in:
     S. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
     Polynomial Basis With Fast Fourier Transform and Its Application to
     Reed–Solomon Erasure Codes," in IEEE Transactions on Information
     Theory, vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi:
     10.1109/TIT.2016.2608892.

   The main macros this file provides are FD_REEDSOL_GENERATE_FFT and
   FD_REEDSOL_GENERATE_IFFT.  The rest of this file is auto-generated
   implementation details.

   Like the normal FFT and IFFT, the operator implemented in this file
   (and henceforward referred to as FFT and IFFT) tranforms between one
   basis and another.  Rather than tranformations of a signal between
   the frequency domain and the time domain, these operators tranform a
   polynomial between domains we call the "evaluation basis" and the
   "coefficient basis".

   In the evaluation basis, a polynomial is represented by its value at
   subsequent points.  Equivalently, the polynomial is represented as a
   linear combination of the Lagrange basis polynomials (briefly, e_i(i)
   = 1, e_i(j)=0 when j != i) . In the coefficient basis, a polynomial
   is represented as a linear combination of basis polynomials for a
   specific, carefully chosen basis fully described in the paper and
   summarized below.

   Let N, a power of 2, be the size of the transform. To define the
   coefficient basis, we first define s_j(x) for j=0, ..., lg(N)
        s_j(x) = x*(x+1)*(x+2)* .. (x+ (2^j-1))
    where the multiplication and addition are GF(2^8) operations, but
    2^j-1 is computed as an integer.  This is equivalent to taking the
    GF product of all elements that are identical to x in all but the
    last j bits.  s_j(x) has order 2^j.

    Now, we define a normalized version, S_j(x) (called s bar in the
    paper):
        S_j(x) = s_j(x) / s_j( 2^j )
    Again, the division is a field operation, but 2^j is an integer
    operation.

    Finally, the basis elements X_i(x) for i=0, ..., N-1 are defined by
    interpreting i as a bitmask and taking the product of the
    corresponding S_j(x) where the bit is set.  For example:
       X_0(x) = 1,
       X_3(x) = S_0(x) * S_1(x),
       X_6(x) = S_1(x) * S_2(x).
    The multiplication happens in GF(2^8) of course.  X_i(x) is a
    polynomial of order i.

   */

#ifndef FD_REEDSOL_GF_ARITH_DEFINED
#error "You must include fd_reedsol_arith_gfni.h or fd_reedsol_arith_avx2.h before including this file"
#endif


/* FD_REEDSOL_GENERATE_FFT: Inserts code to transform n input values from the
   coefficient basis to the evaluation basis, i.e.  evaluating the
   polynomial described by the input at points b, b+1, b+2, ...  b+n-1
   (where this arithmetic on b is integer arithmetic, not GF(2^8)
   arithmetic).

   FD_REEDSOL_GENERATE_IFFT: Inserts code to transform n input values
   from the evaluation basis to the coefficient basis, descrbing a
   polynomial P(x) of degree no more than n such that P(b) = in0,
   P(b+1)=in1, ... P(b+n-1)=in_{n-1} (where this arithmetic on b is
   integer arithmetic, not GF(2^8) arithmetic).

   For both macros, n must be a power of 2 (only 4, 8, 16, 32 are
   emitted by the code generator at the moment), and b must be a
   non-negative multiple of n no more than 32.  Both b and n must be
   literal integer values.

   The remaining n arguments should be vector variables of type gf_t.
   These are used as input and output, since there's no other good way
   to return n vector values.  As such, this macro is not robust.

   The FFT and IFFT are computed in a vectorized fashion, i.e. the
   transform of the ith byte is computed and stored in the ith byte of
   the output for each i independently. */

#define FD_REEDSOL_PRIVATE_EXPAND( M, ... ) M(  __VA_ARGS__ )

#define FD_REEDSOL_GENERATE_FFT(  n, b, ...) FD_REEDSOL_PRIVATE_EXPAND( FD_REEDSOL_FFT_IMPL_##n,   FD_CONCAT4(FD_REEDSOL_FFT_CONSTANTS_,  n, _, b),  __VA_ARGS__ )
#define FD_REEDSOL_GENERATE_IFFT( n, b, ...) FD_REEDSOL_PRIVATE_EXPAND( FD_REEDSOL_IFFT_IMPL_##n,  FD_CONCAT4(FD_REEDSOL_IFFT_CONSTANTS_, n, _, b),  __VA_ARGS__ )




#define FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( inout0, inout1, c)    \
  do {                                                          \
    inout0 = GF_ADD( inout0, GF_MUL( inout1, c ) );             \
    inout1 = GF_ADD( inout1, inout0 );                          \
  } while( 0 )



#define FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( inout0, inout1, c)   \
  do {                                                          \
    inout1 = GF_ADD( inout1, inout0 );                          \
    inout0 = GF_ADD( inout0, GF_MUL( inout1, c ) );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_32_0    0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,   0,   6,  28,  26, 120, 126, 100,  98,   0,  22,  97, 119,   0,  11,   0
#define FD_REEDSOL_IFFT_CONSTANTS_32_32  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62, 237, 235, 241, 247, 149, 147, 137, 143,  38,  48,  71,  81, 174, 165,  71
#define FD_REEDSOL_IFFT_IMPL_32( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16 , \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27 , \
    c_28, c_29, c_30, in00, in01, in02, in03, in04, in05, in06, in07 , \
    in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18 , \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29 , \
    in30, in31)                                                        \
  do {                                                                 \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in01, c_00 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in03, c_01 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in05, c_02 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in07, c_03 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in09, c_04 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in11, c_05 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in13, c_06 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in15, c_07 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in17, c_08 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in19, c_09 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in21, c_10 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in23, c_11 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in25, c_12 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in27, c_13 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in29, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in30, in31, c_15 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_16 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in06, c_17 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in10, c_18 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in14, c_19 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in18, c_20 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in22, c_21 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in26, c_22 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in30, c_23 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in04, c_24 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in12, c_25 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in20, c_26 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in28, c_27 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in08, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in24, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in16, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in24, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in12, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in28, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in20, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in28, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in06, c_24 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in14, c_25 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in22, c_26 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in30, c_27 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in10, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in26, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in18, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in26, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in14, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in30, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in22, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in30, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_16 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in07, c_17 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in11, c_18 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in15, c_19 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in19, c_20 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in23, c_21 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in27, c_22 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in31, c_23 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in05, c_24 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in13, c_25 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in21, c_26 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in29, c_27 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in09, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in25, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in17, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in25, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in13, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in29, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in21, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in29, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in07, c_24 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in15, c_25 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in23, c_26 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in31, c_27 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in11, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in27, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in19, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in27, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in15, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in31, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in23, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in31, c_30 );             \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_32_0    0,   0,  11,   0,  22,  97, 119,   0,   6,  28,  26, 120, 126, 100,  98,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30
#define FD_REEDSOL_FFT_CONSTANTS_32_32  71, 174, 165,  38,  48,  71,  81, 237, 235, 241, 247, 149, 147, 137, 143,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62
#define FD_REEDSOL_FFT_IMPL_32( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16, \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27, \
    c_28, c_29, c_30, in00, in01, in02, in03, in04, in05, in06, in07, \
    in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, \
    in30, in31)                                                       \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in16, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in24, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in08, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in24, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in20, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in28, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in12, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in28, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in04, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in12, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in20, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in28, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in18, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in26, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in10, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in26, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in22, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in30, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in14, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in30, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in06, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in14, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in22, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in30, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in06, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in10, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in14, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in18, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in22, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in26, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in30, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in17, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in25, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in09, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in25, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in21, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in29, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in13, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in29, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in05, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in13, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in21, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in29, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in19, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in27, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in11, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in27, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in23, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in31, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in15, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in31, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in07, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in15, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in23, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in31, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in07, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in11, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in15, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in19, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in23, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in27, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in31, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_15 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_16 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in05, c_17 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in07, c_18 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in09, c_19 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in11, c_20 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in13, c_21 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in15, c_22 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in17, c_23 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in19, c_24 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in21, c_25 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in23, c_26 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in25, c_27 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in27, c_28 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in29, c_29 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in31, c_30 );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_16_0    0,   2,   4,   6,   8,  10,  12,  14,   0,   6,  28,  26,   0,  22,   0
#define FD_REEDSOL_IFFT_CONSTANTS_16_16  16,  18,  20,  22,  24,  26,  28,  30, 120, 126, 100,  98,  97, 119,  11
#define FD_REEDSOL_IFFT_CONSTANTS_16_32  32,  34,  36,  38,  40,  42,  44,  46, 237, 235, 241, 247,  38,  48, 174
#define FD_REEDSOL_IFFT_IMPL_16( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, in00, in01 , \
    in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12 , \
    in13, in14, in15)                                                  \
  do {                                                                 \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in01, c_00 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in03, c_01 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in05, c_02 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in07, c_03 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in09, c_04 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in11, c_05 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in13, c_06 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in15, c_07 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_08 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in06, c_09 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in10, c_10 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in14, c_11 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in04, c_12 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in12, c_13 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in08, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in12, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in06, c_12 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in14, c_13 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in10, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in14, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_08 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in07, c_09 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in11, c_10 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in15, c_11 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in05, c_12 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in13, c_13 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in09, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in13, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in07, c_12 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in15, c_13 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in11, c_14 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in15, c_14 );             \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_16_0    0,   0,  22,   0,   6,  28,  26,   0,   2,   4,   6,   8,  10,  12,  14
#define FD_REEDSOL_FFT_CONSTANTS_16_16  11,  97, 119, 120, 126, 100,  98,  16,  18,  20,  22,  24,  26,  28,  30
#define FD_REEDSOL_FFT_CONSTANTS_16_32 174,  38,  48, 237, 235, 241, 247,  32,  34,  36,  38,  40,  42,  44,  46
#define FD_REEDSOL_FFT_IMPL_16( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, in00, in01, \
    in02, in03, in04, in05, in06, in07, in08, in09, in10, in11, in12, \
    in13, in14, in15)                                                 \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in08, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in12, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in04, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in12, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in10, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in14, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in06, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in14, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in06, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in10, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in14, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in09, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in13, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in05, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in13, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in11, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in15, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in07, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in15, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in07, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in11, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in15, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in05, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in07, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in09, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in11, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in13, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in15, c_14 );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_8_0    0,   2,   4,   6,   0,   6,   0
#define FD_REEDSOL_IFFT_CONSTANTS_8_8    8,  10,  12,  14,  28,  26,  22
#define FD_REEDSOL_IFFT_CONSTANTS_8_16  16,  18,  20,  22, 120, 126,  97
#define FD_REEDSOL_IFFT_CONSTANTS_8_24  24,  26,  28,  30, 100,  98, 119
#define FD_REEDSOL_IFFT_CONSTANTS_8_32  32,  34,  36,  38, 237, 235,  38
#define FD_REEDSOL_IFFT_IMPL_8( c_00, c_01, c_02, c_03, c_04, c_05   , \
    c_06, in00, in01, in02, in03, in04, in05, in06, in07)              \
  do {                                                                 \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in01, c_00 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in03, c_01 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in05, c_02 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in07, c_03 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_04 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in06, c_05 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in04, c_06 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in06, c_06 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_04 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in07, c_05 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in05, c_06 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in07, c_06 );             \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_8_0    0,   0,   6,   0,   2,   4,   6
#define FD_REEDSOL_FFT_CONSTANTS_8_8   22,  28,  26,   8,  10,  12,  14
#define FD_REEDSOL_FFT_CONSTANTS_8_16  97, 120, 126,  16,  18,  20,  22
#define FD_REEDSOL_FFT_CONSTANTS_8_24 119, 100,  98,  24,  26,  28,  30
#define FD_REEDSOL_FFT_CONSTANTS_8_32  38, 237, 235,  32,  34,  36,  38
#define FD_REEDSOL_FFT_IMPL_8( c_00, c_01, c_02, c_03, c_04, c_05   , \
    c_06, in00, in01, in02, in03, in04, in05, in06, in07)             \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in04, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in06, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in06, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in05, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in07, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in07, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in05, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in07, c_06 );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_4_0    0,   2,   0
#define FD_REEDSOL_IFFT_CONSTANTS_4_4    4,   6,   6
#define FD_REEDSOL_IFFT_CONSTANTS_4_8    8,  10,  28
#define FD_REEDSOL_IFFT_CONSTANTS_4_12  12,  14,  26
#define FD_REEDSOL_IFFT_CONSTANTS_4_16  16,  18, 120
#define FD_REEDSOL_IFFT_CONSTANTS_4_20  20,  22, 126
#define FD_REEDSOL_IFFT_CONSTANTS_4_24  24,  26, 100
#define FD_REEDSOL_IFFT_CONSTANTS_4_28  28,  30,  98
#define FD_REEDSOL_IFFT_CONSTANTS_4_32  32,  34, 237
#define FD_REEDSOL_IFFT_IMPL_4( c_00, c_01, c_02, in00, in01, in02   , \
    in03)                                                              \
  do {                                                                 \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in01, c_00 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in03, c_01 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_02 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_02 );             \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_4_0    0,   0,   2
#define FD_REEDSOL_FFT_CONSTANTS_4_4    6,   4,   6
#define FD_REEDSOL_FFT_CONSTANTS_4_8   28,   8,  10
#define FD_REEDSOL_FFT_CONSTANTS_4_12  26,  12,  14
#define FD_REEDSOL_FFT_CONSTANTS_4_16 120,  16,  18
#define FD_REEDSOL_FFT_CONSTANTS_4_20 126,  20,  22
#define FD_REEDSOL_FFT_CONSTANTS_4_24 100,  24,  26
#define FD_REEDSOL_FFT_CONSTANTS_4_28  98,  28,  30
#define FD_REEDSOL_FFT_CONSTANTS_4_32 237,  32,  34
#define FD_REEDSOL_FFT_IMPL_4( c_00, c_01, c_02, in00, in01, in02   , \
    in03)                                                             \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_02 );             \
  } while( 0 )



#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h */
