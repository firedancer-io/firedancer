#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h

#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h
#error "Do not include this file directly; use fd_reedsol_private.h"
#endif

#include "../../util/simd/fd_avx.h"

typedef wb_t gf_t;

#define GF_WIDTH W_FOOTPRINT

FD_PROTOTYPES_BEGIN

#define gf_ldu  wb_ldu
#define gf_stu  wb_stu
#define gf_zero wb_zero

extern uchar const fd_reedsol_arith_consts_gfni_mul[]  __attribute__((aligned(128)));

#define GF_ADD wb_xor

#define GF_OR  wb_or

/* Older versions of GCC have a bug that cause them to think
   _mm256_gf2p8affine_epi64_epi8 is a symmetric in the first two
   arguments (other than that the second argument can be a memory
   address).  That's totally incorrect.  It was fixed in GCC 10.  See
   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92889 for more details. */

#if !FD_USING_CLANG
#define GCC_VERSION (__GNUC__*10000 + __GNUC_MINOR__*100 + __GNUC_PATCHLEVEL__)
#endif

#if FD_USING_CLANG || (GCC_VERSION >= 100000)

#define GF_MUL( a, c ) (__extension__({                                                            \
    wb_t _a = (a);                                                                                 \
    int  _c = (c);                                                                                 \
    /* c is known at compile time, so this is not a runtime branch */                              \
    ((_c==0) ? wb_zero() : ((_c==1) ? _a :                                                         \
     _mm256_gf2p8affine_epi64_epi8( _a, wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*_c ), 0 ) )); \
  }))

#define GF_MUL_VAR( a, c ) (_mm256_gf2p8affine_epi64_epi8( (a), wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*(c) ), 0 ))

#else

#define GF_MUL( a, c ) (__extension__({                                      \
    wb_t _a = (a);                                                           \
    int  _c = (c);                                                           \
    wb_t _product;                                                           \
    __asm__( "vgf2p8affineqb $0x0, %[cons], %[vec], %[out]"                  \
           : [out]"=x"  (_product)                                           \
           : [cons]"xm" (wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*_c )), \
             [vec]"x"   (_a) );                                              \
    /* c is known at compile time, so this is not a runtime branch */        \
    (_c==0) ? wb_zero() : ( (_c==1) ? (_a) : _product );                     \
  }))

#define GF_MUL_VAR( a, c ) (__extension__({                                   \
    wb_t _product;                                                            \
    __asm__( "vgf2p8affineqb $0x0, %[cons], %[vec], %[out]"                   \
           : [out]"=x"  (_product)                                            \
           : [cons]"xm" (wb_ld( fd_reedsol_arith_consts_gfni_mul + 32*(c) )), \
             [vec]"x"   (a) );                                                \
    (_product);                                                               \
  }))

#endif

#define GF_ANY( x ) (0 != _mm256_movemask_epi8( wb_ne( (x), wb_zero() ) ))

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_gfni_h */
