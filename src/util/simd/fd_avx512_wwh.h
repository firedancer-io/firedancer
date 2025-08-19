#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* Vector ushort API **************************************************/

/* A wwh_t is a vector where each 16-bit wide lane holds an unsigned
   16-bit integer (a "ushort").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwh_t __m512i

/* Predefined constants */

#define wwh_zero()           _mm512_setzero_si512()  /* wwh(0, 0, ... 0) */
#define wwh_one()            _mm512_set1_epi32( 1 )  /* wwh(1, 1, ... 1) */

/* Memory operations */
/* Note: wwh_{ld,st} assume m is 64-byte aligned while wwh_{ldu,stu}
   allow m to have arbitrary alignment */

static inline wwh_t wwh_ld( ushort const * m ) { return _mm512_load_epi32( m ); }  /* wwh( m[0], m[1], ... m[15] ) */
static inline void  wwh_st( ushort * m, wwh_t x ) { _mm512_store_epi32( m, x ); }  /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

static inline wwh_t wwh_ldu( void const * m ) { return _mm512_loadu_epi32( m ); } /* wwh( m[0], m[1], ... m[15]) */
static inline void  wwh_stu( void * m, wwh_t x ) { _mm512_storeu_epi32( m, x ); } /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

/* Arithmetic operations */

#define wwh_add(x,y) _mm512_add_epi16( (x), (y) ) /* wwh( x0+y0, x1+y1, ... xf+y31 ) */
#define wwh_sub(x,y) _mm512_sub_epi16( (x), (y) ) /* wwh( x0-y0, x1-y1, ... xf-y31 ) */
