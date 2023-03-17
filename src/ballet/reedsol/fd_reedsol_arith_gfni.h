#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h
#include "../../util/simd/fd_avx.h"

#define FD_REEDSOL_GF_ARITH_DEFINED 1

typedef wb_t gf_t;
#define GF_WIDTH W_FOOTPRINT
#define gf_ldu wb_ldu
#define gf_stu wb_stu
#define gf_zero wb_zero

#ifdef INCLUDE_CONSTANTS
FD_IMPORT_BINARY( fd_reedsol_arith_consts_gfni_mul,    "src/ballet/reedsol/constants/gfni_constants.bin" );
#undef INCLUDE_CONSTANTS
#else
extern uchar const fd_reedsol_arith_consts_gfni_mul[]  __attribute__((aligned(128)));
#endif

#define GF_ADD( a, b ) wb_xor( a, b )

/* Older versions of GCC have a bug that cause them to think
   _mm256_gf2p8affine_epi64_epi8 is a symmetric in the first two arguments
   (other than that the second argument can be a memory address).  That's
   totally incorrect. It was fixed in GCC 10.  See
   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92889 for more details. */
#if !FD_USING_CLANG
#define GCC_VERSION (__GNUC__ * 10000 \
                     + __GNUC_MINOR__ * 100 \
                     + __GNUC_PATCHLEVEL__)
#endif

#if FD_USING_CLANG || (GCC_VERSION >= 100000)
/* c is known at compile time, so this is not a runtime branch */
#define GF_MUL( a, c ) ((c==0) ? wb_zero() : ( (c==1) ? (a) : _mm256_gf2p8affine_epi64_epi8( a, wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*(c) ), 0 ) ))

#else

#define GF_MUL( a, c )  (__extension__({                                       \
      wb_t product;                                                            \
      __asm__( "vgf2p8affineqb $0x0, %[cons], %[vec], %[out]"                  \
          : [out]"=x"(product)                                                 \
          : [cons]"xm"( wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*(c) ) ),  \
            [vec]"x" (a) );                                                    \
      (c==0) ? wb_zero() : ( (c==1) ? (a) : product ); }))

#endif



#endif /*HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h */
