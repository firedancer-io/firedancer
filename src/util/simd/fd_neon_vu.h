#ifndef HEADER_fd_src_util_simd_fd_neon_vu_h
#define HEADER_fd_src_util_simd_fd_neon_vu_h

#ifndef HEADER_fd_src_util_simd_fd_neon_h
#error "Do not include this directly; use fd_neon.h"
#endif

/* Vector uint API ****************************************************/

#define wwu_t uint32x4_t

/* Constructors */

#define wwu(u0,u1,u2,u3) ((uint32x4_t){ (u0), (u1), (u2), (u3) })
#define wwu_bcast(u0) vdupq_n_u32( (u0) )

#define wwu_extract(a,imm) vgetq_lane_u32( (a), (imm) )

/* Predefined constants */

#define wwu_zero() vdupq_n_u32( 0U )
#define wwu_one()  vdupq_n_u32( 1U )

/* Memory operations */

static inline wwu_t wwu_ld( uint const * p )  { return vld1q_u32( p ); }
static inline void  wwu_st( uint * p, wwu_t i ) { vst1q_u32( p, i ); }

static inline wwu_t wwu_ldu( void const * p ) { return vld1q_u32( (uint const *)p ); }
static inline void  wwu_stu( void * p, wwu_t i ) { vst1q_u32( (uint *)p, i ); }

/* Arithmetic operations */

#define wwu_neg(a) vreinterpretq_u32_s32( vnegq_s32( vreinterpretq_s32_u32(a) ) )
#define wwu_abs(a) (a)

#define wwu_min(a,b) vminq_u32( (a), (b) )
#define wwu_max(a,b) vmaxq_u32( (a), (b) )
#define wwu_add(a,b) vaddq_u32( (a), (b) )
#define wwu_sub(a,b) vsubq_u32( (a), (b) )
#define wwu_mul(a,b) vmulq_u32( (a), (b) )

/* Binary operations */

#define wwu_not(a) vmvnq_u32( (a) )

#define wwu_shl(a,imm)  vshlq_n_u32( (a), (imm) )
#define wwu_shr(a,imm)  vshrq_n_u32( (a), (imm) )

#define wwu_and(a,b)    vandq_u32( (a), (b) )
#define wwu_andnot(a,b) vbicq_u32( (b), (a) )
#define wwu_or(a,b)     vorrq_u32( (a), (b) )
#define wwu_xor(a,b)    veorq_u32( (a), (b) )

#define wwu_bswap(x) vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32(x) ) )

/* Logical operations */

#define wwu_eq(a,b) vceqq_u32( (a), (b) )
#define wwu_gt(a,b) vcgtq_u32( (a), (b) )
#define wwu_lt(a,b) vcltq_u32( (a), (b) )
#define wwu_ge(a,b) vcgeq_u32( (a), (b) )
#define wwu_le(a,b) vcleq_u32( (a), (b) )

/* Conditional operations */

#define wwu_if(c,t,f) vbslq_u32( (c), (t), (f) )

#endif /* HEADER_fd_src_util_simd_fd_neon_vu_h */
