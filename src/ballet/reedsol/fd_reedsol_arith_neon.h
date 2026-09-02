#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_neon_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_neon_h

#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_private_h
#error "Do not include this file directly; use fd_reedsol_private.h"
#endif

#include <arm_neon.h>

typedef uint8x16_t gf_t;

#define GF_WIDTH 16UL
#define W_ATTR   __attribute__((aligned(16)))

FD_PROTOTYPES_BEGIN

static inline gf_t gf_ldu( uchar const * addr        ) { return vld1q_u8( addr ); }
static inline void gf_stu( uchar       * addr, gf_t v ) { vst1q_u8( addr, v );    }

#define gf_zero() vdupq_n_u8( 0 )

extern uchar const fd_reedsol_arith_consts_neon_mul[]  __attribute__((aligned(128)));

#define GF_ADD veorq_u8

#define GF_OR  vorrq_u8

#define GF_MUL_VAR( a, c ) (__extension__({                                                       \
    uint8x16_t _a  = (a);                                                                         \
    ulong      _c  = (ulong)(c);                                                                  \
    uint8x16_t _lo = vandq_u8( _a, vdupq_n_u8( 0x0F ) );                                          \
    uint8x16_t _hi = vshrq_n_u8( _a, 4 );                                                         \
    uint8x16_t _p0 = vqtbl1q_u8( vld1q_u8( fd_reedsol_arith_consts_neon_mul +          16UL*_c ), _lo ); \
    uint8x16_t _p1 = vqtbl1q_u8( vld1q_u8( fd_reedsol_arith_consts_neon_mul + 4096UL + 16UL*_c ), _hi ); \
    veorq_u8( _p0, _p1 );                                                                         \
  }))

#define GF_MUL( a, c ) (__extension__({                                     \
    uint8x16_t _ma = (a);                                                   \
    int        _mc = (c);                                                   \
    (_mc==0) ? gf_zero() : ( (_mc==1) ? _ma : GF_MUL_VAR( _ma, _mc ) );     \
  }))

#define GF_ANY( x ) (0U != vmaxvq_u8( (x) ))

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_arith_neon_h */
