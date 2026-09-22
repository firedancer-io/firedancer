#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

#if !FD_HAS_RISCV_ED25519
#error "RISC-V Ed25519 backend requires FD_HAS_RISCV_ED25519"
#endif

#if !defined(__riscv_v) || (__riscv_xlen!=64) || (__riscv_v_min_vlen<128)
#error "RISC-V Ed25519 backend requires RV64V with VLEN >= 128"
#endif

#include <riscv_vector.h>

/* The generic field representation has five radix-51 limbs.  Ed25519 point
   formulas naturally issue three or four independent field operations at a
   time.  Put those operations in e64,m1 lanes, processing two at a time at the
   minimum supported VLEN of 128 bits and four at a time at VLEN >= 256.  vmul
   and vmulhu together reconstruct each exact 128-bit product used by the Fiat
   scalar implementation.

   Inputs are loaded with indexed operations because the API permits unrelated
   field-element pointers.  The implementation does not stage secret field
   data in memory; the small arrays in the wrappers below contain addresses
   only. */

#if defined(__GNUC__) && !defined(__clang__)
#define FD_F25519_RVV_HELPER __attribute__((noinline,optimize("no-tree-vectorize")))
#else
#define FD_F25519_RVV_HELPER __attribute__((noinline))
#endif

#define FD_F25519_RVV_LOAD( addr, idx )                                        \
  __riscv_vluxei64_v_u64m1( (ulong const *)0,                                 \
                            __riscv_vadd_vx_u64m1( (addr), 8UL*(idx), vl ), vl )

#define FD_F25519_RVV_LOAD19( addr, idx )                                      \
  __riscv_vmul_vx_u64m1( FD_F25519_RVV_LOAD( (addr), (idx) ), 19UL, vl )

#define FD_F25519_RVV_LOAD2( addr, idx )                                       \
  __riscv_vsll_vx_u64m1( FD_F25519_RVV_LOAD( (addr), (idx) ), 1U, vl )

#define FD_F25519_RVV_LOAD38( addr, idx )                                      \
  __riscv_vmul_vx_u64m1( FD_F25519_RVV_LOAD( (addr), (idx) ), 38UL, vl )

#define FD_F25519_RVV_ACCUM( x, y ) do {                                      \
    vuint64m1_t _pl = __riscv_vmul_vv_u64m1  ( (x), (y), vl );                \
    vuint64m1_t _ph = __riscv_vmulhu_vv_u64m1( (x), (y), vl );                \
    vbool64_t   _cy = __riscv_vmadc_vv_u64m1_b64( lo, _pl, vl );              \
    hi = __riscv_vadc_vvm_u64m1( hi, _ph, _cy, vl );                          \
    lo = __riscv_vadd_vv_u64m1( lo, _pl, vl );                                \
    FD_COMPILER_MFENCE();                                                       \
  } while(0)

#define FD_F25519_RVV_COEFF3( x0,y0, x1,y1, x2,y2 ) do {                      \
    vuint64m1_t _x = (x0);                                                     \
    vuint64m1_t _y = (y0);                                                     \
    lo = __riscv_vmul_vv_u64m1  ( _x, _y, vl );                               \
    hi = __riscv_vmulhu_vv_u64m1( _x, _y, vl );                               \
    FD_COMPILER_MFENCE();                                                       \
    _x = (x1); _y = (y1); FD_F25519_RVV_ACCUM( _x, _y );                      \
    _x = (x2); _y = (y2); FD_F25519_RVV_ACCUM( _x, _y );                      \
  } while(0)

#define FD_F25519_RVV_COEFF5( x0,y0, x1,y1, x2,y2, x3,y3, x4,y4 ) do {        \
    FD_F25519_RVV_COEFF3( (x0),(y0), (x1),(y1), (x2),(y2) );                  \
    vuint64m1_t _x = (x3);                                                     \
    vuint64m1_t _y = (y3);                                                     \
    FD_F25519_RVV_ACCUM( _x, _y );                                            \
    _x = (x4); _y = (y4); FD_F25519_RVV_ACCUM( _x, _y );                      \
  } while(0)

#define FD_F25519_RVV_FIRST_LIMB( rk ) do {                                   \
    (rk) = __riscv_vand_vx_u64m1( lo, mask, vl );                             \
    cy = __riscv_vor_vv_u64m1( __riscv_vsrl_vx_u64m1( lo, 51U, vl ),         \
                               __riscv_vsll_vx_u64m1( hi, 13U, vl ), vl );     \
  } while(0)

#define FD_F25519_RVV_NEXT_LIMB( rk ) do {                                    \
    vbool64_t _cc = __riscv_vmadc_vv_u64m1_b64( lo, cy, vl );                 \
    lo = __riscv_vadd_vv_u64m1( lo, cy, vl );                                 \
    hi = __riscv_vadc_vxm_u64m1( hi, 0UL, _cc, vl );                          \
    (rk) = __riscv_vand_vx_u64m1( lo, mask, vl );                             \
    cy = __riscv_vor_vv_u64m1( __riscv_vsrl_vx_u64m1( lo, 51U, vl ),         \
                               __riscv_vsll_vx_u64m1( hi, 13U, vl ), vl );     \
  } while(0)

#define FD_F25519_RVV_STORE_LIMBS() do {                                      \
    r0 = __riscv_vadd_vv_u64m1( r0, __riscv_vmul_vx_u64m1( cy, 19UL, vl ), vl ); \
    r1 = __riscv_vadd_vv_u64m1( r1, __riscv_vsrl_vx_u64m1( r0, 51U, vl ), vl ); \
    r2 = __riscv_vadd_vv_u64m1( r2, __riscv_vsrl_vx_u64m1( r1, 51U, vl ), vl ); \
    r0 = __riscv_vand_vx_u64m1( r0, mask, vl );                               \
    r1 = __riscv_vand_vx_u64m1( r1, mask, vl );                               \
    vuint64m1_t _addr = __riscv_vle64_v_u64m1( raddr, vl );                   \
    __riscv_vsuxei64_v_u64m1( (ulong *)0, _addr, r0, vl );                    \
    _addr = __riscv_vadd_vx_u64m1( _addr, 8UL, vl );                          \
    __riscv_vsuxei64_v_u64m1( (ulong *)0, _addr, r1, vl );                    \
    _addr = __riscv_vadd_vx_u64m1( _addr, 8UL, vl );                          \
    __riscv_vsuxei64_v_u64m1( (ulong *)0, _addr, r2, vl );                    \
    _addr = __riscv_vadd_vx_u64m1( _addr, 8UL, vl );                          \
    __riscv_vsuxei64_v_u64m1( (ulong *)0, _addr, r3, vl );                    \
    _addr = __riscv_vadd_vx_u64m1( _addr, 8UL, vl );                          \
    __riscv_vsuxei64_v_u64m1( (ulong *)0, _addr, r4, vl );                    \
  } while(0)

static FD_F25519_RVV_HELPER void
fd_f25519_rvv_muln( ulong const raddr_all[4],
                    ulong const aaddr_all[4],
                    ulong const baddr_all[4],
                    ulong       cnt ) {
  for( ulong done=0UL; done<cnt; ) {
    ulong const vl = __riscv_vsetvl_e64m1( cnt-done );
    ulong const * raddr = raddr_all + done;
    ulong const mask = (1UL<<51) - 1UL;
    vuint64m1_t aa = __riscv_vle64_v_u64m1( aaddr_all+done, vl );
    vuint64m1_t ba = __riscv_vle64_v_u64m1( baddr_all+done, vl );
    vuint64m1_t lo;
    vuint64m1_t hi;
    vuint64m1_t cy;
    vuint64m1_t r0;
    vuint64m1_t r1;
    vuint64m1_t r2;
    vuint64m1_t r3;
    vuint64m1_t r4;

  FD_F25519_RVV_COEFF5( FD_F25519_RVV_LOAD( aa, 0 ), FD_F25519_RVV_LOAD( ba, 0 ),
                        FD_F25519_RVV_LOAD( aa, 1 ), FD_F25519_RVV_LOAD19( ba, 4 ),
                        FD_F25519_RVV_LOAD( aa, 2 ), FD_F25519_RVV_LOAD19( ba, 3 ),
                        FD_F25519_RVV_LOAD( aa, 3 ), FD_F25519_RVV_LOAD19( ba, 2 ),
                        FD_F25519_RVV_LOAD( aa, 4 ), FD_F25519_RVV_LOAD19( ba, 1 ) );
  FD_F25519_RVV_FIRST_LIMB( r0 );
  FD_F25519_RVV_COEFF5( FD_F25519_RVV_LOAD( aa, 0 ), FD_F25519_RVV_LOAD( ba, 1 ),
                        FD_F25519_RVV_LOAD( aa, 1 ), FD_F25519_RVV_LOAD( ba, 0 ),
                        FD_F25519_RVV_LOAD( aa, 2 ), FD_F25519_RVV_LOAD19( ba, 4 ),
                        FD_F25519_RVV_LOAD( aa, 3 ), FD_F25519_RVV_LOAD19( ba, 3 ),
                        FD_F25519_RVV_LOAD( aa, 4 ), FD_F25519_RVV_LOAD19( ba, 2 ) );
  FD_F25519_RVV_NEXT_LIMB( r1 );
  FD_F25519_RVV_COEFF5( FD_F25519_RVV_LOAD( aa, 0 ), FD_F25519_RVV_LOAD( ba, 2 ),
                        FD_F25519_RVV_LOAD( aa, 1 ), FD_F25519_RVV_LOAD( ba, 1 ),
                        FD_F25519_RVV_LOAD( aa, 2 ), FD_F25519_RVV_LOAD( ba, 0 ),
                        FD_F25519_RVV_LOAD( aa, 3 ), FD_F25519_RVV_LOAD19( ba, 4 ),
                        FD_F25519_RVV_LOAD( aa, 4 ), FD_F25519_RVV_LOAD19( ba, 3 ) );
  FD_F25519_RVV_NEXT_LIMB( r2 );
  FD_F25519_RVV_COEFF5( FD_F25519_RVV_LOAD( aa, 0 ), FD_F25519_RVV_LOAD( ba, 3 ),
                        FD_F25519_RVV_LOAD( aa, 1 ), FD_F25519_RVV_LOAD( ba, 2 ),
                        FD_F25519_RVV_LOAD( aa, 2 ), FD_F25519_RVV_LOAD( ba, 1 ),
                        FD_F25519_RVV_LOAD( aa, 3 ), FD_F25519_RVV_LOAD( ba, 0 ),
                        FD_F25519_RVV_LOAD( aa, 4 ), FD_F25519_RVV_LOAD19( ba, 4 ) );
  FD_F25519_RVV_NEXT_LIMB( r3 );
  FD_F25519_RVV_COEFF5( FD_F25519_RVV_LOAD( aa, 0 ), FD_F25519_RVV_LOAD( ba, 4 ),
                        FD_F25519_RVV_LOAD( aa, 1 ), FD_F25519_RVV_LOAD( ba, 3 ),
                        FD_F25519_RVV_LOAD( aa, 2 ), FD_F25519_RVV_LOAD( ba, 2 ),
                        FD_F25519_RVV_LOAD( aa, 3 ), FD_F25519_RVV_LOAD( ba, 1 ),
                        FD_F25519_RVV_LOAD( aa, 4 ), FD_F25519_RVV_LOAD( ba, 0 ) );
  FD_F25519_RVV_NEXT_LIMB( r4 );
    FD_F25519_RVV_STORE_LIMBS();
    done += vl;
  }
}

static FD_F25519_RVV_HELPER void
fd_f25519_rvv_sqrn( ulong const raddr_all[4],
                    ulong const aaddr_all[4],
                    ulong       cnt ) {
  for( ulong done=0UL; done<cnt; ) {
    ulong const vl = __riscv_vsetvl_e64m1( cnt-done );
    ulong const * raddr = raddr_all + done;
    ulong const mask = (1UL<<51) - 1UL;
    vuint64m1_t aa = __riscv_vle64_v_u64m1( aaddr_all+done, vl );
    vuint64m1_t lo;
    vuint64m1_t hi;
    vuint64m1_t cy;
    vuint64m1_t r0;
    vuint64m1_t r1;
    vuint64m1_t r2;
    vuint64m1_t r3;
    vuint64m1_t r4;

  FD_F25519_RVV_COEFF3( FD_F25519_RVV_LOAD( aa, 0 ),   FD_F25519_RVV_LOAD( aa, 0 ),
                        FD_F25519_RVV_LOAD38( aa, 1 ), FD_F25519_RVV_LOAD( aa, 4 ),
                        FD_F25519_RVV_LOAD38( aa, 2 ), FD_F25519_RVV_LOAD( aa, 3 ) );
  FD_F25519_RVV_FIRST_LIMB( r0 );
  FD_F25519_RVV_COEFF3( FD_F25519_RVV_LOAD2( aa, 0 ),  FD_F25519_RVV_LOAD( aa, 1 ),
                        FD_F25519_RVV_LOAD38( aa, 2 ), FD_F25519_RVV_LOAD( aa, 4 ),
                        FD_F25519_RVV_LOAD19( aa, 3 ), FD_F25519_RVV_LOAD( aa, 3 ) );
  FD_F25519_RVV_NEXT_LIMB( r1 );
  FD_F25519_RVV_COEFF3( FD_F25519_RVV_LOAD2( aa, 0 ),  FD_F25519_RVV_LOAD( aa, 2 ),
                        FD_F25519_RVV_LOAD( aa, 1 ),   FD_F25519_RVV_LOAD( aa, 1 ),
                        FD_F25519_RVV_LOAD38( aa, 3 ), FD_F25519_RVV_LOAD( aa, 4 ) );
  FD_F25519_RVV_NEXT_LIMB( r2 );
  FD_F25519_RVV_COEFF3( FD_F25519_RVV_LOAD2( aa, 0 ),  FD_F25519_RVV_LOAD( aa, 3 ),
                        FD_F25519_RVV_LOAD2( aa, 1 ),  FD_F25519_RVV_LOAD( aa, 2 ),
                        FD_F25519_RVV_LOAD19( aa, 4 ), FD_F25519_RVV_LOAD( aa, 4 ) );
  FD_F25519_RVV_NEXT_LIMB( r3 );
  FD_F25519_RVV_COEFF3( FD_F25519_RVV_LOAD2( aa, 0 ), FD_F25519_RVV_LOAD( aa, 4 ),
                        FD_F25519_RVV_LOAD2( aa, 1 ), FD_F25519_RVV_LOAD( aa, 3 ),
                        FD_F25519_RVV_LOAD( aa, 2 ),  FD_F25519_RVV_LOAD( aa, 2 ) );
  FD_F25519_RVV_NEXT_LIMB( r4 );
    FD_F25519_RVV_STORE_LIMBS();
    done += vl;
  }
}

/* fd_f25519_muln computes r_i = a_i * b_i. */
FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, 0UL, 0UL };
  ulong a[4] = { (ulong)a1, (ulong)a2, 0UL, 0UL };
  ulong b[4] = { (ulong)b1, (ulong)b2, 0UL, 0UL };
  fd_f25519_rvv_muln( r, a, b, 2UL );
}

FD_25519_INLINE void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, (ulong)r3, 0UL };
  ulong a[4] = { (ulong)a1, (ulong)a2, (ulong)a3, 0UL };
  ulong b[4] = { (ulong)b1, (ulong)b2, (ulong)b3, 0UL };
  fd_f25519_rvv_muln( r, a, b, 3UL );
}

FD_25519_INLINE void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, (ulong)r3, (ulong)r4 };
  ulong a[4] = { (ulong)a1, (ulong)a2, (ulong)a3, (ulong)a4 };
  ulong b[4] = { (ulong)b1, (ulong)b2, (ulong)b3, (ulong)b4 };
  fd_f25519_rvv_muln( r, a, b, 4UL );
}

/* fd_f25519_sqrn computes r_i = a_i^2. */
FD_25519_INLINE void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, 0UL, 0UL };
  ulong a[4] = { (ulong)a1, (ulong)a2, 0UL, 0UL };
  fd_f25519_rvv_sqrn( r, a, 2UL );
}

FD_25519_INLINE void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, (ulong)r3, 0UL };
  ulong a[4] = { (ulong)a1, (ulong)a2, (ulong)a3, 0UL };
  fd_f25519_rvv_sqrn( r, a, 3UL );
}

FD_25519_INLINE void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 ) {
  ulong r[4] = { (ulong)r1, (ulong)r2, (ulong)r3, (ulong)r4 };
  ulong a[4] = { (ulong)a1, (ulong)a2, (ulong)a3, (ulong)a4 };
  fd_f25519_rvv_sqrn( r, a, 4UL );
}

#undef FD_F25519_RVV_STORE_LIMBS
#undef FD_F25519_RVV_NEXT_LIMB
#undef FD_F25519_RVV_FIRST_LIMB
#undef FD_F25519_RVV_COEFF5
#undef FD_F25519_RVV_COEFF3
#undef FD_F25519_RVV_ACCUM
#undef FD_F25519_RVV_LOAD38
#undef FD_F25519_RVV_LOAD2
#undef FD_F25519_RVV_LOAD19
#undef FD_F25519_RVV_LOAD
#undef FD_F25519_RVV_HELPER
