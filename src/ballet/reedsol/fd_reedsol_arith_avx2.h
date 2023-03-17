#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_avx2_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_avx2_h
#include "../../util/simd/fd_avx.h"

#define FD_REEDSOL_GF_ARITH_DEFINED 1

typedef wb_t gf_t;
#define GF_WIDTH W_FOOTPRINT
#define gf_ldu wb_ldu
#define gf_stu wb_stu
#define gf_zero wb_zero

#ifdef INCLUDE_CONSTANTS
FD_IMPORT_BINARY( fd_reedsol_arith_consts_avx_mul,    "src/ballet/reedsol/constants/avx2_constants.bin" );
#undef INCLUDE_CONSTANTS
#else
extern uchar const fd_reedsol_arith_consts_avx_mul[]  __attribute__((aligned(128)));
#endif

static uchar const fd_reedsol_arith_scale4[ 256UL ] = {
  0,  16,  32,  48,  64,  80,  96, 112, 128, 144, 160, 176, 192, 208, 224, 240,  29,  13,  61,  45,  93,  77, 125, 109, 157, 141, 189, 173, 221, 205, 253, 237,  58,  42,  26,  10, 122,
  106,  90,  74, 186, 170, 154, 138, 250, 234, 218, 202,  39,  55,   7,  23, 103, 119,  71,  87, 167, 183, 135, 151, 231, 247, 199, 215, 116, 100,  84,  68,  52,  36,  20,   4, 244, 228,
  212, 196, 180, 164, 148, 132, 105, 121,  73,  89,  41,  57,   9,  25, 233, 249, 201, 217, 169, 185, 137, 153,  78,  94, 110, 126,  14,  30,  46,  62, 206, 222, 238, 254, 142, 158, 174,
  190,  83,  67, 115,  99,  19,   3,  51,  35, 211, 195, 243, 227, 147, 131, 179, 163, 232, 248, 200, 216, 168, 184, 136, 152, 104, 120,  72,  88,  40,  56,   8,  24, 245, 229, 213, 197,
  181, 165, 149, 133, 117, 101,  85,  69,  53,  37,  21,   5, 210, 194, 242, 226, 146, 130, 178, 162,  82,  66, 114,  98,  18,   2,  50,  34, 207, 223, 239, 255, 143, 159, 175, 191,  79,
  95, 111, 127,  15,  31,  47,  63, 156, 140, 188, 172, 220, 204, 252, 236,  28,  12,  60,  44,  92,  76, 124, 108, 129, 145, 161, 177, 193, 209, 225, 241,   1,  17,  33,  49,  65,  81,
  97, 113, 166, 182, 134, 150, 230, 246, 198, 214,  38,  54,   6,  22, 102, 118,  70,  86, 187, 171, 155, 139, 251, 235, 219, 203,  59,  43,  27,  11, 123, 107,  91,  75 }; /* Needs to be available at compile time, not link time, to allow the optimizer to use it */

#define GF_ADD wb_xor
#define GF_OR  wb_or
#define GF_MUL( a, c ) (__extension__({                                                                            \
  wb_t lo = wb_and( a, wb_bcast( 0x0F ) );                                                                         \
  wb_t hi = wb_shr( a, 4 );                                                                                        \
  wb_t p0 = _mm256_shuffle_epi8( wb_ld( fd_reedsol_arith_consts_avx_mul + 32*c ), lo );                            \
  wb_t p1 = _mm256_shuffle_epi8( wb_ld( fd_reedsol_arith_consts_avx_mul + 32*fd_reedsol_arith_scale4[ c ] ), hi ); \
  /* c is known at compile time, so this is not a runtime branch */                                                \
  (c==0) ? wb_zero() : ( (c==1) ? a : wb_xor( p0, p1 ) ); } ))



#endif /*HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_avx2_h */
