#ifndef HEADER_fd_src_util_simd_fd_neon_vi_h
#define HEADER_fd_src_util_simd_fd_neon_vi_h

#ifndef HEADER_fd_src_util_simd_fd_neon_h
#error "Do not include this directly; use fd_neon.h"
#endif

/* Vector int API *****************************************************/

#define wwi_t int32x4_t

/* Constructors */

#define wwi(i0,i1,i2,i3) ((int32x4_t){ (i0), (i1), (i2), (i3) })
#define wwi_bcast(i0) vdupq_n_s32( (i0) )

#define wwi_extract(a,imm) vgetq_lane_s32( (a), (imm) )

/* Predefined constants */

#define wwi_zero() vdupq_n_s32( 0 )
#define wwi_one()  vdupq_n_s32( 1 )

/* Memory operations */

static inline wwi_t wwi_ld( int const * p )  { return vld1q_s32( p ); }
static inline void  wwi_st( int * p, wwi_t i ) { vst1q_s32( p, i ); }

static inline wwi_t wwi_ldu( void const * p ) { return vld1q_s32( (int const *)p ); }
static inline void  wwi_stu( void * p, wwi_t i ) { vst1q_s32( (int *)p, i ); }

/* Arithmetic operations */

#define wwi_neg(a) vnegq_s32( (a) )
#define wwi_abs(a) vabsq_s32( (a) )

#define wwi_min(a,b) vminq_s32( (a), (b) )
#define wwi_max(a,b) vmaxq_s32( (a), (b) )
#define wwi_add(a,b) vaddq_s32( (a), (b) )
#define wwi_sub(a,b) vsubq_s32( (a), (b) )
#define wwi_mul(a,b) vmulq_s32( (a), (b) )

/* Binary operations */

#define wwi_not(a) vmvnq_s32( (a) )

#define wwi_shl(a,imm)  vshlq_n_s32( (a), (imm) )
#define wwi_shr(a,imm)  vshrq_n_s32( (a), (imm) )
#define wwi_shru(a,imm) vreinterpretq_s32_u32( vshrq_n_u32( vreinterpretq_u32_s32(a), (imm) ) )

#define wwi_and(a,b)    vandq_s32( (a), (b) )
#define wwi_andnot(a,b) vbicq_s32( (b), (a) ) /* Note argument swap for vbic (b & ~a) */
#define wwi_or(a,b)     vorrq_s32( (a), (b) )
#define wwi_xor(a,b)    veorq_s32( (a), (b) )

/* Logical operations */

#define wwi_eq(a,b) vreinterpretq_s32_u32( vceqq_s32( (a), (b) ) )
#define wwi_gt(a,b) vreinterpretq_s32_u32( vcgtq_s32( (a), (b) ) )
#define wwi_lt(a,b) vreinterpretq_s32_u32( vcltq_s32( (a), (b) ) )
#define wwi_ge(a,b) vreinterpretq_s32_u32( vcgeq_s32( (a), (b) ) )
#define wwi_le(a,b) vreinterpretq_s32_u32( vcleq_s32( (a), (b) ) )

/* Conditional operations */

#define wwi_if(c,t,f) vbslq_s32( vreinterpretq_u32_s32(c), (t), (f) )

#endif /* HEADER_fd_src_util_simd_fd_neon_vi_h */
