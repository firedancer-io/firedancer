
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



#define FD_REEDSOL_IFFT_CONSTANTS_128_0    0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,   0,   6,  28,  26, 120, 126, 100,  98, 237, 235, 241, 247, 149, 147, 137, 143, 179, 181, 175, 169, 203, 205, 215, 209,  94,  88,  66,  68,  38,  32,  58,  60,   0,  22,  97, 119,  38,  48,  71,  81, 183, 161, 214, 192, 145, 135, 240, 230,   0,  11, 174, 165,  33,  42, 143, 132,   0,  71, 189, 250,   0, 218,   0
#define FD_REEDSOL_IFFT_CONSTANTS_128_128 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 182, 176, 170, 172, 206, 200, 210, 212,  91,  93,  71,  65,  35,  37,  63,  57,   5,   3,  25,  31, 125, 123,  97, 103, 232, 238, 244, 242, 144, 150, 140, 138,  12,  26, 109, 123,  42,  60,  75,  93, 187, 173, 218, 204, 157, 139, 252, 234,  45,  38, 131, 136,  12,   7, 162, 169,  18,  85, 175, 232, 130,  88, 133
#define FD_REEDSOL_IFFT_IMPL_128( c_00, c_01, c_02, c_03, c_04, c_05    , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16    , \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27    , \
    c_28, c_29, c_30, c_31, c_32, c_33, c_34, c_35, c_36, c_37, c_38    , \
    c_39, c_40, c_41, c_42, c_43, c_44, c_45, c_46, c_47, c_48, c_49    , \
    c_50, c_51, c_52, c_53, c_54, c_55, c_56, c_57, c_58, c_59, c_60    , \
    c_61, c_62, c_63, c_64, c_65, c_66, c_67, c_68, c_69, c_70, c_71    , \
    c_72, c_73, c_74, c_75, c_76, c_77, c_78, c_79, c_80, c_81, c_82    , \
    c_83, c_84, c_85, c_86, c_87, c_88, c_89, c_90, c_91, c_92, c_93    , \
    c_94, c_95, c_96, c_97, c_98, c_99, c_100, c_101, c_102, c_103, c_104, \
    c_105, c_106, c_107, c_108, c_109, c_110, c_111, c_112, c_113, c_114, \
    c_115, c_116, c_117, c_118, c_119, c_120, c_121, c_122, c_123, c_124, \
    c_125, c_126, in00, in01, in02, in03, in04, in05, in06, in07, in08  , \
    in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19    , \
    in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30    , \
    in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41    , \
    in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52    , \
    in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63    , \
    in64, in65, in66, in67, in68, in69, in70, in71, in72, in73, in74    , \
    in75, in76, in77, in78, in79, in80, in81, in82, in83, in84, in85    , \
    in86, in87, in88, in89, in90, in91, in92, in93, in94, in95, in96    , \
    in97, in98, in99, in100, in101, in102, in103, in104, in105, in106   , \
    in107, in108, in109, in110, in111, in112, in113, in114, in115, in116, \
    in117, in118, in119, in120, in121, in122, in123, in124, in125, in126, \
    in127)                                                                \
  do {                                                                    \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in01, c_00 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in03, c_01 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in05, c_02 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in07, c_03 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in09, c_04 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in11, c_05 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in13, c_06 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in15, c_07 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in17, c_08 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in19, c_09 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in21, c_10 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in23, c_11 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in25, c_12 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in27, c_13 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in29, c_14 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in30, in31, c_15 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in33, c_16 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in35, c_17 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in37, c_18 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in39, c_19 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in41, c_20 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in43, c_21 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in45, c_22 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in46, in47, c_23 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in49, c_24 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in51, c_25 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in53, c_26 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in54, in55, c_27 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in57, c_28 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in58, in59, c_29 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in60, in61, c_30 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in62, in63, c_31 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in65, c_32 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in66, in67, c_33 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in68, in69, c_34 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in70, in71, c_35 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in72, in73, c_36 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in74, in75, c_37 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in76, in77, c_38 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in78, in79, c_39 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in80, in81, c_40 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in82, in83, c_41 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in84, in85, c_42 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in86, in87, c_43 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in88, in89, c_44 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in90, in91, c_45 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in92, in93, c_46 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in94, in95, c_47 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in96, in97, c_48 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in98, in99, c_49 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in100, in101, c_50 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in102, in103, c_51 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in104, in105, c_52 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in106, in107, c_53 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in108, in109, c_54 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in110, in111, c_55 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in112, in113, c_56 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in114, in115, c_57 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in116, in117, c_58 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in118, in119, c_59 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in120, in121, c_60 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in122, in123, c_61 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in124, in125, c_62 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in126, in127, c_63 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_64 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in06, c_65 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in10, c_66 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in14, c_67 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in18, c_68 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in22, c_69 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in26, c_70 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in30, c_71 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in34, c_72 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in38, c_73 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in42, c_74 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in46, c_75 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in50, c_76 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in54, c_77 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in58, c_78 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in60, in62, c_79 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in66, c_80 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in68, in70, c_81 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in72, in74, c_82 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in76, in78, c_83 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in80, in82, c_84 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in84, in86, c_85 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in88, in90, c_86 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in92, in94, c_87 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in96, in98, c_88 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in100, in102, c_89 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in104, in106, c_90 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in108, in110, c_91 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in112, in114, c_92 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in116, in118, c_93 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in120, in122, c_94 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in124, in126, c_95 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in04, c_96 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in12, c_97 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in20, c_98 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in28, c_99 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in36, c_100 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in44, c_101 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in52, c_102 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in60, c_103 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in68, c_104 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in72, in76, c_105 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in80, in84, c_106 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in88, in92, c_107 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in96, in100, c_108 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in104, in108, c_109 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in112, in116, c_110 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in120, in124, c_111 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in08, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in24, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in40, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in56, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in72, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in80, in88, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in96, in104, c_118 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in112, in120, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in16, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in48, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in80, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in96, in112, c_123 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in32, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in64, in96, c_125 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in64, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in96, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in48, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in80, in112, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in80, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in112, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in24, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in56, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in72, in88, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in104, in120, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in40, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in72, in104, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in72, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in104, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in56, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in88, in120, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in88, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in120, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in12, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in28, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in44, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in60, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in68, in76, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in84, in92, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in100, in108, c_118 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in116, in124, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in20, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in52, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in68, in84, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in100, in116, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in36, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in68, in100, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in68, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in100, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in52, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in84, in116, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in84, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in116, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in28, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in60, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in76, in92, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in108, in124, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in44, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in76, in108, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in76, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in108, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in60, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in92, in124, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in92, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in60, in124, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in06, c_96 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in14, c_97 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in22, c_98 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in30, c_99 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in38, c_100 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in46, c_101 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in54, c_102 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in58, in62, c_103 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in66, in70, c_104 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in74, in78, c_105 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in82, in86, c_106 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in90, in94, c_107 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in98, in102, c_108 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in106, in110, c_109 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in114, in118, c_110 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in122, in126, c_111 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in10, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in26, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in42, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in58, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in66, in74, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in82, in90, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in98, in106, c_118 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in114, in122, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in18, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in50, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in66, in82, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in98, in114, c_123 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in34, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in66, in98, c_125 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in66, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in98, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in50, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in82, in114, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in82, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in114, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in26, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in58, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in74, in90, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in106, in122, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in42, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in74, in106, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in74, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in106, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in58, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in90, in122, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in90, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in58, in122, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in14, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in30, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in46, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in54, in62, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in70, in78, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in86, in94, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in102, in110, c_118 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in118, in126, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in22, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in54, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in70, in86, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in102, in118, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in38, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in70, in102, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in70, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in102, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in54, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in86, in118, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in86, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in54, in118, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in30, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in46, in62, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in78, in94, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in110, in126, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in46, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in78, in110, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in78, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in46, in110, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in30, in62, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in94, in126, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in30, in94, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in62, in126, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_64 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in07, c_65 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in11, c_66 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in15, c_67 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in19, c_68 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in23, c_69 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in27, c_70 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in31, c_71 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in35, c_72 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in39, c_73 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in43, c_74 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in45, in47, c_75 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in51, c_76 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in53, in55, c_77 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in57, in59, c_78 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in61, in63, c_79 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in65, in67, c_80 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in69, in71, c_81 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in73, in75, c_82 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in77, in79, c_83 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in81, in83, c_84 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in85, in87, c_85 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in89, in91, c_86 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in93, in95, c_87 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in97, in99, c_88 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in101, in103, c_89 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in105, in107, c_90 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in109, in111, c_91 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in113, in115, c_92 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in117, in119, c_93 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in121, in123, c_94 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in125, in127, c_95 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in05, c_96 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in13, c_97 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in21, c_98 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in29, c_99 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in37, c_100 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in45, c_101 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in53, c_102 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in57, in61, c_103 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in65, in69, c_104 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in73, in77, c_105 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in81, in85, c_106 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in89, in93, c_107 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in97, in101, c_108 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in105, in109, c_109 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in113, in117, c_110 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in121, in125, c_111 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in09, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in25, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in41, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in57, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in65, in73, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in81, in89, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in97, in105, c_118 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in113, in121, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in17, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in49, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in65, in81, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in97, in113, c_123 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in33, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in65, in97, c_125 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in65, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in97, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in49, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in81, in113, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in81, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in113, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in25, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in57, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in73, in89, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in105, in121, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in41, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in73, in105, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in73, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in105, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in57, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in89, in121, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in89, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in57, in121, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in13, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in29, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in45, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in53, in61, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in69, in77, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in85, in93, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in101, in109, c_118 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in117, in125, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in21, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in53, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in69, in85, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in101, in117, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in37, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in69, in101, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in69, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in101, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in53, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in85, in117, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in85, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in53, in117, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in29, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in45, in61, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in77, in93, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in109, in125, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in45, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in77, in109, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in77, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in45, in109, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in61, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in93, in125, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in93, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in61, in125, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in07, c_96 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in15, c_97 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in23, c_98 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in31, c_99 );                \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in39, c_100 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in43, in47, c_101 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in51, in55, c_102 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in59, in63, c_103 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in67, in71, c_104 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in75, in79, c_105 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in83, in87, c_106 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in91, in95, c_107 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in99, in103, c_108 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in107, in111, c_109 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in115, in119, c_110 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in123, in127, c_111 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in11, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in27, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in43, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in51, in59, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in67, in75, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in83, in91, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in99, in107, c_118 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in115, in123, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in19, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in51, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in67, in83, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in99, in115, c_123 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in35, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in67, in99, c_125 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in67, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in99, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in51, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in83, in115, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in83, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in51, in115, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in27, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in43, in59, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in75, in91, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in107, in123, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in43, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in75, in107, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in75, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in43, in107, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in59, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in91, in123, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in91, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in59, in123, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in15, c_112 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in31, c_113 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in39, in47, c_114 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in55, in63, c_115 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in71, in79, c_116 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in87, in95, c_117 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in103, in111, c_118 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in119, in127, c_119 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in23, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in39, in55, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in71, in87, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in103, in119, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in39, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in71, in103, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in71, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in39, in103, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in55, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in87, in119, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in87, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in55, in119, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in31, c_120 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in47, in63, c_121 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in79, in95, c_122 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in111, in127, c_123 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in47, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in79, in111, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in79, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in47, in111, c_126 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in31, in63, c_124 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in95, in127, c_125 );              \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in31, in95, c_126 );               \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in63, in127, c_126 );              \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_128_0    0,   0, 218,   0,  71, 189, 250,   0,  11, 174, 165,  33,  42, 143, 132,   0,  22,  97, 119,  38,  48,  71,  81, 183, 161, 214, 192, 145, 135, 240, 230,   0,   6,  28,  26, 120, 126, 100,  98, 237, 235, 241, 247, 149, 147, 137, 143, 179, 181, 175, 169, 203, 205, 215, 209,  94,  88,  66,  68,  38,  32,  58,  60,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126
#define FD_REEDSOL_FFT_CONSTANTS_128_128 133, 130,  88,  18,  85, 175, 232,  45,  38, 131, 136,  12,   7, 162, 169,  12,  26, 109, 123,  42,  60,  75,  93, 187, 173, 218, 204, 157, 139, 252, 234, 182, 176, 170, 172, 206, 200, 210, 212,  91,  93,  71,  65,  35,  37,  63,  57,   5,   3,  25,  31, 125, 123,  97, 103, 232, 238, 244, 242, 144, 150, 140, 138, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254
#define FD_REEDSOL_FFT_CONSTANTS_128_256   0,   0, 218,   0,  71, 189, 250,   0,  11, 174, 165,  33,  42, 143, 132,   0,  22,  97, 119,  38,  48,  71,  81, 183, 161, 214, 192, 145, 135, 240, 230,   0,   6,  28,  26, 120, 126, 100,  98, 237, 235, 241, 247, 149, 147, 137, 143, 179, 181, 175, 169, 203, 205, 215, 209,  94,  88,  66,  68,  38,  32,  58,  60,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126
#define FD_REEDSOL_FFT_IMPL_128( c_00, c_01, c_02, c_03, c_04, c_05    , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16   , \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27   , \
    c_28, c_29, c_30, c_31, c_32, c_33, c_34, c_35, c_36, c_37, c_38   , \
    c_39, c_40, c_41, c_42, c_43, c_44, c_45, c_46, c_47, c_48, c_49   , \
    c_50, c_51, c_52, c_53, c_54, c_55, c_56, c_57, c_58, c_59, c_60   , \
    c_61, c_62, c_63, c_64, c_65, c_66, c_67, c_68, c_69, c_70, c_71   , \
    c_72, c_73, c_74, c_75, c_76, c_77, c_78, c_79, c_80, c_81, c_82   , \
    c_83, c_84, c_85, c_86, c_87, c_88, c_89, c_90, c_91, c_92, c_93   , \
    c_94, c_95, c_96, c_97, c_98, c_99, c_100, c_101, c_102, c_103     , \
    c_104, c_105, c_106, c_107, c_108, c_109, c_110, c_111, c_112, c_113, \
    c_114, c_115, c_116, c_117, c_118, c_119, c_120, c_121, c_122, c_123, \
    c_124, c_125, c_126, in00, in01, in02, in03, in04, in05, in06, in07, \
    in08, in09, in10, in11, in12, in13, in14, in15, in16, in17, in18   , \
    in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29   , \
    in30, in31, in32, in33, in34, in35, in36, in37, in38, in39, in40   , \
    in41, in42, in43, in44, in45, in46, in47, in48, in49, in50, in51   , \
    in52, in53, in54, in55, in56, in57, in58, in59, in60, in61, in62   , \
    in63, in64, in65, in66, in67, in68, in69, in70, in71, in72, in73   , \
    in74, in75, in76, in77, in78, in79, in80, in81, in82, in83, in84   , \
    in85, in86, in87, in88, in89, in90, in91, in92, in93, in94, in95   , \
    in96, in97, in98, in99, in100, in101, in102, in103, in104, in105   , \
    in106, in107, in108, in109, in110, in111, in112, in113, in114, in115, \
    in116, in117, in118, in119, in120, in121, in122, in123, in124, in125, \
    in126, in127)                                                        \
  do {                                                                   \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in64, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in96, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in32, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in96, c_02 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in80, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in112, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in48, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in80, in112, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in16, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in48, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in80, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in96, in112, c_06 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in72, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in104, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in40, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in72, in104, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in88, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in120, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in56, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in88, in120, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in24, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in56, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in72, in88, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in104, in120, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in08, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in24, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in40, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in56, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in72, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in80, in88, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in96, in104, c_13 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in112, in120, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in68, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in100, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in36, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in68, in100, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in84, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in116, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in52, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in84, in116, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in20, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in52, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in68, in84, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in100, in116, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in76, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in108, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in44, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in76, in108, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in92, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in60, in124, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in60, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in92, in124, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in28, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in60, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in76, in92, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in108, in124, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in12, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in28, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in44, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in60, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in68, in76, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in84, in92, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in100, in108, c_13 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in116, in124, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in04, c_15 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in12, c_16 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in20, c_17 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in28, c_18 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in36, c_19 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in44, c_20 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in52, c_21 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in60, c_22 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in68, c_23 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in72, in76, c_24 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in80, in84, c_25 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in88, in92, c_26 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in96, in100, c_27 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in104, in108, c_28 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in112, in116, c_29 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in120, in124, c_30 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in66, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in98, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in34, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in66, in98, c_02 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in82, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in114, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in50, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in82, in114, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in18, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in50, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in66, in82, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in98, in114, c_06 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in74, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in106, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in42, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in74, in106, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in90, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in58, in122, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in58, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in90, in122, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in26, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in58, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in74, in90, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in106, in122, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in10, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in26, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in42, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in58, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in66, in74, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in82, in90, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in98, in106, c_13 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in114, in122, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in70, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in102, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in38, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in70, in102, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in86, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in54, in118, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in54, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in86, in118, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in22, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in54, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in70, in86, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in102, in118, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in78, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in46, in110, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in46, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in78, in110, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in94, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in62, in126, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in62, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in94, in126, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in30, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in46, in62, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in78, in94, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in110, in126, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in14, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in30, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in46, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in54, in62, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in70, in78, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in86, in94, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in102, in110, c_13 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in118, in126, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in06, c_15 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in14, c_16 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in22, c_17 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in30, c_18 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in38, c_19 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in46, c_20 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in54, c_21 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in58, in62, c_22 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in66, in70, c_23 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in74, in78, c_24 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in82, in86, c_25 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in90, in94, c_26 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in98, in102, c_27 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in106, in110, c_28 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in114, in118, c_29 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in122, in126, c_30 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_31 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in06, c_32 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in10, c_33 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in14, c_34 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in18, c_35 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in22, c_36 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in26, c_37 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in30, c_38 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in34, c_39 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in38, c_40 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in42, c_41 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in46, c_42 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in50, c_43 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in54, c_44 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in58, c_45 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in60, in62, c_46 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in66, c_47 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in68, in70, c_48 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in72, in74, c_49 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in76, in78, c_50 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in80, in82, c_51 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in84, in86, c_52 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in88, in90, c_53 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in92, in94, c_54 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in96, in98, c_55 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in100, in102, c_56 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in104, in106, c_57 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in108, in110, c_58 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in112, in114, c_59 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in116, in118, c_60 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in120, in122, c_61 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in124, in126, c_62 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in65, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in97, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in33, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in65, in97, c_02 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in81, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in113, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in49, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in81, in113, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in17, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in49, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in65, in81, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in97, in113, c_06 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in73, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in105, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in41, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in73, in105, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in89, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in57, in121, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in57, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in89, in121, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in25, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in57, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in73, in89, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in105, in121, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in09, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in25, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in41, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in57, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in65, in73, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in81, in89, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in97, in105, c_13 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in113, in121, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in69, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in101, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in37, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in69, in101, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in85, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in53, in117, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in53, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in85, in117, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in21, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in53, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in69, in85, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in101, in117, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in77, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in45, in109, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in45, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in77, in109, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in93, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in61, in125, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in61, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in93, in125, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in29, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in45, in61, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in77, in93, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in109, in125, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in13, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in29, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in45, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in53, in61, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in69, in77, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in85, in93, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in101, in109, c_13 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in117, in125, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in05, c_15 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in13, c_16 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in21, c_17 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in29, c_18 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in37, c_19 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in45, c_20 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in53, c_21 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in57, in61, c_22 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in65, in69, c_23 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in73, in77, c_24 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in81, in85, c_25 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in89, in93, c_26 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in97, in101, c_27 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in105, in109, c_28 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in113, in117, c_29 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in121, in125, c_30 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in67, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in99, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in35, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in67, in99, c_02 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in83, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in51, in115, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in51, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in83, in115, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in19, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in51, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in67, in83, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in99, in115, c_06 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in75, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in43, in107, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in43, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in75, in107, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in91, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in59, in123, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in59, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in91, in123, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in27, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in43, in59, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in75, in91, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in107, in123, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in11, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in27, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in43, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in51, in59, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in67, in75, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in83, in91, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in99, in107, c_13 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in115, in123, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in71, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in39, in103, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in39, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in71, in103, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in87, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in55, in119, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in55, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in87, in119, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in23, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in39, in55, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in71, in87, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in103, in119, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in79, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in47, in111, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in47, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in79, in111, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in31, in95, c_00 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in63, in127, c_00 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in31, in63, c_01 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in95, in127, c_02 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in31, c_03 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in47, in63, c_04 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in79, in95, c_05 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in111, in127, c_06 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in15, c_07 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in31, c_08 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in39, in47, c_09 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in55, in63, c_10 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in71, in79, c_11 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in87, in95, c_12 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in103, in111, c_13 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in119, in127, c_14 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in07, c_15 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in15, c_16 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in23, c_17 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in31, c_18 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in39, c_19 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in43, in47, c_20 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in51, in55, c_21 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in59, in63, c_22 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in67, in71, c_23 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in75, in79, c_24 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in83, in87, c_25 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in91, in95, c_26 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in99, in103, c_27 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in107, in111, c_28 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in115, in119, c_29 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in123, in127, c_30 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_31 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in07, c_32 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in11, c_33 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in15, c_34 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in19, c_35 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in23, c_36 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in27, c_37 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in31, c_38 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in35, c_39 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in39, c_40 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in43, c_41 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in45, in47, c_42 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in51, c_43 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in53, in55, c_44 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in57, in59, c_45 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in61, in63, c_46 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in65, in67, c_47 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in69, in71, c_48 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in73, in75, c_49 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in77, in79, c_50 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in81, in83, c_51 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in85, in87, c_52 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in89, in91, c_53 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in93, in95, c_54 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in97, in99, c_55 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in101, in103, c_56 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in105, in107, c_57 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in109, in111, c_58 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in113, in115, c_59 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in117, in119, c_60 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in121, in123, c_61 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in125, in127, c_62 );              \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_63 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_64 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in05, c_65 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in07, c_66 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in09, c_67 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in11, c_68 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in13, c_69 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in15, c_70 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in17, c_71 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in19, c_72 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in21, c_73 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in23, c_74 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in25, c_75 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in27, c_76 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in29, c_77 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in31, c_78 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in33, c_79 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in35, c_80 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in37, c_81 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in39, c_82 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in41, c_83 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in43, c_84 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in45, c_85 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in46, in47, c_86 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in49, c_87 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in51, c_88 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in53, c_89 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in54, in55, c_90 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in57, c_91 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in58, in59, c_92 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in60, in61, c_93 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in62, in63, c_94 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in64, in65, c_95 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in66, in67, c_96 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in68, in69, c_97 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in70, in71, c_98 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in72, in73, c_99 );                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in74, in75, c_100 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in76, in77, c_101 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in78, in79, c_102 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in80, in81, c_103 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in82, in83, c_104 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in84, in85, c_105 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in86, in87, c_106 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in88, in89, c_107 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in90, in91, c_108 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in92, in93, c_109 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in94, in95, c_110 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in96, in97, c_111 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in98, in99, c_112 );               \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in100, in101, c_113 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in102, in103, c_114 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in104, in105, c_115 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in106, in107, c_116 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in108, in109, c_117 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in110, in111, c_118 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in112, in113, c_119 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in114, in115, c_120 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in116, in117, c_121 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in118, in119, c_122 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in120, in121, c_123 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in122, in123, c_124 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in124, in125, c_125 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in126, in127, c_126 );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_64_0    0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62,   0,   6,  28,  26, 120, 126, 100,  98, 237, 235, 241, 247, 149, 147, 137, 143,   0,  22,  97, 119,  38,  48,  71,  81,   0,  11, 174, 165,   0,  71,   0
#define FD_REEDSOL_IFFT_CONSTANTS_64_64  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 179, 181, 175, 169, 203, 205, 215, 209,  94,  88,  66,  68,  38,  32,  58,  60, 183, 161, 214, 192, 145, 135, 240, 230,  33,  42, 143, 132, 189, 250, 218
#define FD_REEDSOL_IFFT_CONSTANTS_64_128 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 182, 176, 170, 172, 206, 200, 210, 212,  91,  93,  71,  65,  35,  37,  63,  57,  12,  26, 109, 123,  42,  60,  75,  93,  45,  38, 131, 136,  18,  85, 130
#define FD_REEDSOL_IFFT_IMPL_64( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16 , \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27 , \
    c_28, c_29, c_30, c_31, c_32, c_33, c_34, c_35, c_36, c_37, c_38 , \
    c_39, c_40, c_41, c_42, c_43, c_44, c_45, c_46, c_47, c_48, c_49 , \
    c_50, c_51, c_52, c_53, c_54, c_55, c_56, c_57, c_58, c_59, c_60 , \
    c_61, c_62, in00, in01, in02, in03, in04, in05, in06, in07, in08 , \
    in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19 , \
    in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30 , \
    in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41 , \
    in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52 , \
    in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63)  \
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
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in33, c_16 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in35, c_17 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in37, c_18 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in39, c_19 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in41, c_20 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in43, c_21 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in45, c_22 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in46, in47, c_23 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in49, c_24 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in51, c_25 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in53, c_26 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in54, in55, c_27 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in57, c_28 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in58, in59, c_29 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in60, in61, c_30 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in62, in63, c_31 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in02, c_32 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in06, c_33 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in10, c_34 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in14, c_35 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in18, c_36 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in22, c_37 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in26, c_38 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in30, c_39 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in34, c_40 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in38, c_41 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in42, c_42 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in46, c_43 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in50, c_44 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in54, c_45 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in58, c_46 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in60, in62, c_47 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in04, c_48 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in12, c_49 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in20, c_50 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in28, c_51 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in36, c_52 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in44, c_53 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in52, c_54 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in56, in60, c_55 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in08, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in24, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in40, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in48, in56, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in16, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in32, in48, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in00, in32, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in16, in48, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in24, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in40, in56, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in08, in40, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in24, in56, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in12, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in28, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in44, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in52, in60, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in20, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in36, in52, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in04, in36, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in20, in52, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in28, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in44, in60, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in12, in44, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in28, in60, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in06, c_48 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in14, c_49 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in22, c_50 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in30, c_51 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in38, c_52 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in46, c_53 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in54, c_54 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in58, in62, c_55 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in10, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in26, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in42, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in50, in58, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in18, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in34, in50, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in02, in34, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in18, in50, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in26, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in42, in58, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in10, in42, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in26, in58, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in14, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in30, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in46, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in54, in62, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in22, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in38, in54, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in06, in38, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in22, in54, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in30, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in46, in62, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in14, in46, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in30, in62, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in03, c_32 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in07, c_33 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in11, c_34 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in15, c_35 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in19, c_36 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in23, c_37 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in27, c_38 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in31, c_39 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in35, c_40 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in39, c_41 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in43, c_42 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in45, in47, c_43 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in51, c_44 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in53, in55, c_45 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in57, in59, c_46 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in61, in63, c_47 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in05, c_48 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in13, c_49 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in21, c_50 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in29, c_51 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in37, c_52 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in45, c_53 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in53, c_54 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in57, in61, c_55 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in09, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in25, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in41, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in49, in57, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in17, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in33, in49, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in01, in33, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in17, in49, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in25, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in41, in57, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in09, in41, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in25, in57, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in13, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in29, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in45, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in53, in61, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in21, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in37, in53, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in05, in37, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in21, in53, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in29, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in45, in61, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in13, in45, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in29, in61, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in07, c_48 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in15, c_49 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in23, c_50 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in31, c_51 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in39, c_52 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in43, in47, c_53 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in51, in55, c_54 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in59, in63, c_55 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in11, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in27, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in43, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in51, in59, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in19, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in35, in51, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in03, in35, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in19, in51, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in27, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in43, in59, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in11, in43, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in27, in59, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in15, c_56 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in31, c_57 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in39, in47, c_58 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in55, in63, c_59 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in23, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in39, in55, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in07, in39, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in23, in55, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in31, c_60 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in47, in63, c_61 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in15, in47, c_62 );             \
    FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( in31, in63, c_62 );             \
  } while( 0 )



#define FD_REEDSOL_FFT_CONSTANTS_64_0    0,   0,  71,   0,  11, 174, 165,   0,  22,  97, 119,  38,  48,  71,  81,   0,   6,  28,  26, 120, 126, 100,  98, 237, 235, 241, 247, 149, 147, 137, 143,   0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62
#define FD_REEDSOL_FFT_CONSTANTS_64_64 218, 189, 250,  33,  42, 143, 132, 183, 161, 214, 192, 145, 135, 240, 230, 179, 181, 175, 169, 203, 205, 215, 209,  94,  88,  66,  68,  38,  32,  58,  60,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126
#define FD_REEDSOL_FFT_CONSTANTS_64_128 130,  18,  85,  45,  38, 131, 136,  12,  26, 109, 123,  42,  60,  75,  93, 182, 176, 170, 172, 206, 200, 210, 212,  91,  93,  71,  65,  35,  37,  63,  57, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190
#define FD_REEDSOL_FFT_IMPL_64( c_00, c_01, c_02, c_03, c_04, c_05  , \
    c_06, c_07, c_08, c_09, c_10, c_11, c_12, c_13, c_14, c_15, c_16, \
    c_17, c_18, c_19, c_20, c_21, c_22, c_23, c_24, c_25, c_26, c_27, \
    c_28, c_29, c_30, c_31, c_32, c_33, c_34, c_35, c_36, c_37, c_38, \
    c_39, c_40, c_41, c_42, c_43, c_44, c_45, c_46, c_47, c_48, c_49, \
    c_50, c_51, c_52, c_53, c_54, c_55, c_56, c_57, c_58, c_59, c_60, \
    c_61, c_62, in00, in01, in02, in03, in04, in05, in06, in07, in08, \
    in09, in10, in11, in12, in13, in14, in15, in16, in17, in18, in19, \
    in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, \
    in31, in32, in33, in34, in35, in36, in37, in38, in39, in40, in41, \
    in42, in43, in44, in45, in46, in47, in48, in49, in50, in51, in52, \
    in53, in54, in55, in56, in57, in58, in59, in60, in61, in62, in63) \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in32, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in48, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in16, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in48, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in40, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in56, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in24, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in56, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in08, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in24, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in40, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in56, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in36, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in52, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in20, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in52, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in44, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in60, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in28, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in60, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in12, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in28, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in44, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in60, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in04, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in12, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in20, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in28, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in36, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in44, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in52, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in60, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in34, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in50, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in18, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in50, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in42, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in58, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in26, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in58, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in10, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in26, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in42, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in58, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in38, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in54, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in22, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in54, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in46, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in62, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in30, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in46, in62, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in14, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in30, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in46, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in54, in62, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in06, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in14, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in22, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in30, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in38, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in46, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in54, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in58, in62, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_15 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in06, c_16 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in10, c_17 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in14, c_18 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in18, c_19 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in22, c_20 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in26, c_21 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in30, c_22 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in34, c_23 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in38, c_24 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in42, c_25 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in46, c_26 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in50, c_27 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in54, c_28 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in58, c_29 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in60, in62, c_30 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in33, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in49, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in17, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in49, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in41, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in57, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in25, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in57, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in09, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in25, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in41, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in57, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in37, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in53, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in21, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in53, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in45, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in61, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in29, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in45, in61, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in13, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in29, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in45, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in53, in61, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in05, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in13, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in21, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in29, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in37, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in45, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in53, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in57, in61, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in35, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in51, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in19, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in51, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in43, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in59, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in27, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in43, in59, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in11, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in27, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in43, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in51, in59, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in39, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in55, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in23, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in39, in55, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in47, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in31, in63, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in15, in31, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in47, in63, c_02 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in07, in15, c_03 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in23, in31, c_04 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in39, in47, c_05 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in55, in63, c_06 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in03, in07, c_07 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in11, in15, c_08 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in19, in23, c_09 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in27, in31, c_10 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in35, in39, c_11 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in43, in47, c_12 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in51, in55, c_13 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in59, in63, c_14 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_15 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in05, in07, c_16 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in09, in11, c_17 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in13, in15, c_18 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in17, in19, c_19 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in21, in23, c_20 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in25, in27, c_21 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in29, in31, c_22 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in33, in35, c_23 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in37, in39, c_24 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in41, in43, c_25 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in45, in47, c_26 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in49, in51, c_27 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in53, in55, c_28 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in57, in59, c_29 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in61, in63, c_30 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_31 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_32 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in04, in05, c_33 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in06, in07, c_34 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in08, in09, c_35 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in10, in11, c_36 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in12, in13, c_37 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in14, in15, c_38 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in16, in17, c_39 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in18, in19, c_40 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in20, in21, c_41 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in22, in23, c_42 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in24, in25, c_43 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in26, in27, c_44 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in28, in29, c_45 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in30, in31, c_46 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in32, in33, c_47 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in34, in35, c_48 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in36, in37, c_49 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in38, in39, c_50 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in40, in41, c_51 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in42, in43, c_52 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in44, in45, c_53 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in46, in47, c_54 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in48, in49, c_55 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in50, in51, c_56 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in52, in53, c_57 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in54, in55, c_58 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in56, in57, c_59 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in58, in59, c_60 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in60, in61, c_61 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in62, in63, c_62 );             \
  } while( 0 )



#define FD_REEDSOL_IFFT_CONSTANTS_32_0    0,   2,   4,   6,   8,  10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,   0,   6,  28,  26, 120, 126, 100,  98,   0,  22,  97, 119,   0,  11,   0
#define FD_REEDSOL_IFFT_CONSTANTS_32_32  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,  62, 237, 235, 241, 247, 149, 147, 137, 143,  38,  48,  71,  81, 174, 165,  71
#define FD_REEDSOL_IFFT_CONSTANTS_32_64  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94, 179, 181, 175, 169, 203, 205, 215, 209, 183, 161, 214, 192,  33,  42, 189
#define FD_REEDSOL_IFFT_CONSTANTS_32_96  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,  94,  88,  66,  68,  38,  32,  58,  60, 145, 135, 240, 230, 143, 132, 250
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
#define FD_REEDSOL_FFT_CONSTANTS_32_64 189,  33,  42, 183, 161, 214, 192, 179, 181, 175, 169, 203, 205, 215, 209,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,  88,  90,  92,  94
#define FD_REEDSOL_FFT_CONSTANTS_32_96 250, 143, 132, 145, 135, 240, 230,  94,  88,  66,  68,  38,  32,  58,  60,  96,  98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126
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
#define FD_REEDSOL_IFFT_CONSTANTS_16_48  48,  50,  52,  54,  56,  58,  60,  62, 149, 147, 137, 143,  71,  81, 165
#define FD_REEDSOL_IFFT_CONSTANTS_16_64  64,  66,  68,  70,  72,  74,  76,  78, 179, 181, 175, 169, 183, 161,  33
#define FD_REEDSOL_IFFT_CONSTANTS_16_80  80,  82,  84,  86,  88,  90,  92,  94, 203, 205, 215, 209, 214, 192,  42
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
#define FD_REEDSOL_FFT_CONSTANTS_16_48 165,  71,  81, 149, 147, 137, 143,  48,  50,  52,  54,  56,  58,  60,  62
#define FD_REEDSOL_FFT_CONSTANTS_16_64  33, 183, 161, 179, 181, 175, 169,  64,  66,  68,  70,  72,  74,  76,  78
#define FD_REEDSOL_FFT_CONSTANTS_16_80  42, 214, 192, 203, 205, 215, 209,  80,  82,  84,  86,  88,  90,  92,  94
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
#define FD_REEDSOL_IFFT_CONSTANTS_8_40  40,  42,  44,  46, 241, 247,  48
#define FD_REEDSOL_IFFT_CONSTANTS_8_48  48,  50,  52,  54, 149, 147,  71
#define FD_REEDSOL_IFFT_CONSTANTS_8_56  56,  58,  60,  62, 137, 143,  81
#define FD_REEDSOL_IFFT_CONSTANTS_8_64  64,  66,  68,  70, 179, 181, 183
#define FD_REEDSOL_IFFT_CONSTANTS_8_72  72,  74,  76,  78, 175, 169, 161
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
#define FD_REEDSOL_FFT_CONSTANTS_8_40  48, 241, 247,  40,  42,  44,  46
#define FD_REEDSOL_FFT_CONSTANTS_8_48  71, 149, 147,  48,  50,  52,  54
#define FD_REEDSOL_FFT_CONSTANTS_8_56  81, 137, 143,  56,  58,  60,  62
#define FD_REEDSOL_FFT_CONSTANTS_8_64 183, 179, 181,  64,  66,  68,  70
#define FD_REEDSOL_FFT_CONSTANTS_8_72 161, 175, 169,  72,  74,  76,  78
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
#define FD_REEDSOL_IFFT_CONSTANTS_4_36  36,  38, 235
#define FD_REEDSOL_IFFT_CONSTANTS_4_40  40,  42, 241
#define FD_REEDSOL_IFFT_CONSTANTS_4_44  44,  46, 247
#define FD_REEDSOL_IFFT_CONSTANTS_4_48  48,  50, 149
#define FD_REEDSOL_IFFT_CONSTANTS_4_52  52,  54, 147
#define FD_REEDSOL_IFFT_CONSTANTS_4_56  56,  58, 137
#define FD_REEDSOL_IFFT_CONSTANTS_4_60  60,  62, 143
#define FD_REEDSOL_IFFT_CONSTANTS_4_64  64,  66, 179
#define FD_REEDSOL_IFFT_CONSTANTS_4_68  68,  70, 181
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
#define FD_REEDSOL_FFT_CONSTANTS_4_36 235,  36,  38
#define FD_REEDSOL_FFT_CONSTANTS_4_40 241,  40,  42
#define FD_REEDSOL_FFT_CONSTANTS_4_44 247,  44,  46
#define FD_REEDSOL_FFT_CONSTANTS_4_48 149,  48,  50
#define FD_REEDSOL_FFT_CONSTANTS_4_52 147,  52,  54
#define FD_REEDSOL_FFT_CONSTANTS_4_56 137,  56,  58
#define FD_REEDSOL_FFT_CONSTANTS_4_60 143,  60,  62
#define FD_REEDSOL_FFT_CONSTANTS_4_64 179,  64,  66
#define FD_REEDSOL_FFT_CONSTANTS_4_68 181,  68,  70
#define FD_REEDSOL_FFT_IMPL_4( c_00, c_01, c_02, in00, in01, in02   , \
    in03)                                                             \
  do {                                                                \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in02, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in01, in03, c_00 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in00, in01, c_01 );             \
    FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( in02, in03, c_02 );             \
  } while( 0 )



#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h */
