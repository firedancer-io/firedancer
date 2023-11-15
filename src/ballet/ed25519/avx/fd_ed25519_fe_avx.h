#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#error "Do not include this; use fd_ed25519_private.h"
#endif

/* Some quick extensions to the wl APIs useful here */

/* wl_addn adds up the n wls. */

#define wl_add0()                       wl_zero()
#define wl_add1(  a                   ) (a)
#define wl_add2(  a,b                 ) wl_add( (a), (b) )
#define wl_add3(  a,b,c               ) wl_add2( wl_add2( (a),(b) ),             (c) )
#define wl_add4(  a,b,c,d             ) wl_add2( wl_add2( (a),(b) ),             wl_add2( (c),(d) ) )
#define wl_add5(  a,b,c,d,e           ) wl_add2( wl_add3( (a),(b),(c) ),         wl_add2( (d),(e) ) )
#define wl_add6(  a,b,c,d,e,f         ) wl_add2( wl_add3( (a),(b),(c) ),         wl_add3( (d),(e),(f) ) )
#define wl_add7(  a,b,c,d,e,f,g       ) wl_add2( wl_add4( (a),(b),(c),(d) ),     wl_add3( (e),(f),(g) ) )
#define wl_add8(  a,b,c,d,e,f,g,h     ) wl_add2( wl_add4( (a),(b),(c),(d) ),     wl_add4( (e),(f),(g),(h) ) )
#define wl_add9(  a,b,c,d,e,f,g,h,i   ) wl_add2( wl_add5( (a),(b),(c),(d),(e) ), wl_add4( (f),(g),(h),(i) ) )
#define wl_add10( a,b,c,d,e,f,g,h,i,j ) wl_add2( wl_add5( (a),(b),(c),(d),(e) ), wl_add5( (f),(g),(h),(i),(j) ) )

FD_PROTOTYPES_BEGIN

/* wl_shr_x19 returns [ (x0>>n)*19L (x1>>n)*19L ... (x3>>n)*19L ] */

static inline wl_t
wl_shr_x19( wl_t x,
            int  n ) {
  x = wl_shr( x, n );
  return wl_add3( x, wl_shl( x, 1 ), wl_shl( x, 4 ) );
}

/* wl_dbl_mix(f) for f = [fa fb fc fd] returns
   [fa-fb-fc fb+fc fc-fc fd-fb+fc] */

static inline wl_t
wl_dbl_mix( wl_t f ) {
  wl_t _zero = wl_zero();           /* Should be hoisted */
  wl_t _mask = wl(-1L, 0L, 0L,-1L); /* Should be hoisted */
  wl_t _tmp  = wl_permute( f, 1,0,2,3 );                       /* = [ fb  fa  fc  fd ] */
  _tmp = _mm256_unpacklo_epi64( _tmp, wl_sub( _zero, _tmp ) ); /* = [ fb -fb  fc -fc ] */
  return wl_add3( wl_and( f, _mask ),                          /* = [ fa   0   0  fd ] */
                  wl_permute( _tmp, 1,0,0,1 ),                 /* + [-fb  fb  fb -fb ] */
                  wl_permute( _tmp, 3,2,3,2 ) );               /* + [-fc  fc -fc  fc ] */
}

/* wl_sub_mix(f) for f = [fa fb fc fd] returns
   [fc-fb fc+fb 2*fa-fd 2*fa+fd] */

static inline wl_t
wl_sub_mix( wl_t f ) {
  wl_t _zero = wl_zero();           /* Should be hoisted */
  wl_t _mask = wl( 0L, 0L,-1L,-1L); /* Should be hoisted */
  wl_t _tmp = wl_permute( f, 2,2,0,0 );                             /* tmp = [  Z  Z  X  X ] */
  return wl_add3( _tmp,                                             /* h   = [  Z  Z  X  X ] */
                  wl_and( _tmp, _mask ),                            /*     + [  0  0  X  X ] */
                  _mm256_unpackhi_epi64( wl_sub( _zero, f ), f ) ); /*     + [ -Y  Y -T  T ] */
}

/* wl_subadd_12(f) for f = [fa fb fc fd] returns
   [fa fb-fc fb+fc fd] */

static inline wl_t
wl_subadd_12( wl_t f ) {
  wl_t _zero = wl_zero();           /* Should be hoisted */
  wl_t _mask = wl( 0L,-1L,-1L, 0L); /* Should be hoisted */
  wl_t _tmp = wl_permute( f, 2,2,2,2 );                                                   /* tmp = [  C  C  C  C ] */ \
  return wl_add( wl_permute( f, 0,1,1,3 ),                                                /* h   = [  A  B  B  D ] */ \
                 wl_and( _mm256_unpacklo_epi64( _tmp, wl_sub( _zero, _tmp ) ), _mask ) ); /*     + [  0 -C  C  0 ] */
}

/* wl_addsub_12(f) for f = [fa fb fc fd] returns
   [fa fb+fc fb-fc fd] */

static inline wl_t
wl_addsub_12( wl_t f ) {
  wl_t _zero = wl_zero();         /* Should be hoisted */
  wl_t _mask = wl( 0L,1L,1L, 0L); /* Should be hoisted */
  wl_t _tmp = wl_permute( f, 2,2,2,2 );                                                   /* tmp = [  C  C  C  C ] */ \
  return wl_add( wl_permute( f, 0,1,1,3 ),                                                /* h   = [  A  B  B  D ] */ \
                 wl_and( _mm256_unpacklo_epi64( _tmp, wl_sub( _zero, _tmp ) ), _mask ) ); /*     + [  0  C -C  0 ] */
}

FD_PROTOTYPES_END

#include "fd_ed25519_fe_avx_inl.h"

FD_PROTOTYPES_BEGIN

static inline long *
fe_avx_ld4( long *                  z,
            fd_ed25519_fe_t const * a,
            fd_ed25519_fe_t const * b,
            fd_ed25519_fe_t const * c,
            fd_ed25519_fe_t const * d ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_SWIZZLE_IN4( vz, a, b, c, d );
  FE_AVX_INL_ST( z, vz );
  return z;
}

static inline long *
fe_avx_ld3( long *                  z,
            fd_ed25519_fe_t const * a,
            fd_ed25519_fe_t const * b,
            fd_ed25519_fe_t const * c ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_SWIZZLE_IN3( vz, a, b, c );
  FE_AVX_INL_ST( z, vz );
  return z;
}

static inline long *
fe_avx_ld2( long *                  z,
            fd_ed25519_fe_t const * a,
            fd_ed25519_fe_t const * b ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_SWIZZLE_IN2( vz, a, b );
  FE_AVX_INL_ST( z, vz );
  return z;
}

static inline void
fe_avx_st4( fd_ed25519_fe_t * a,
            fd_ed25519_fe_t * b,
            fd_ed25519_fe_t * c,
            fd_ed25519_fe_t * d,
            long *            z ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_LD( vz, z );
  FE_AVX_INL_SWIZZLE_OUT4( a, b, c, d, vz );
}

static inline void
fe_avx_st3( fd_ed25519_fe_t * a,
            fd_ed25519_fe_t * b,
            fd_ed25519_fe_t * c,
            long *            z ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_LD( vz, z );
  FE_AVX_INL_SWIZZLE_OUT3( a, b, c, vz );
}

static inline void
fe_avx_st2( fd_ed25519_fe_t * a,
            fd_ed25519_fe_t * b,
            long *            z ) {
  FE_AVX_INL_DECL( vz );
  FE_AVX_INL_LD( vz, z );
  FE_AVX_INL_SWIZZLE_OUT2( a, b, vz );
}

static inline long *
fe_avx_zero( long * z ) {
  FE_AVX_INL_DECL( vx    );
  FE_AVX_INL_ZERO( vx    );
  FE_AVX_INL_ST  ( z, vx );
  return z;
}

static inline long *
fe_avx_permute( long *       z,
                long const * x,
                int          imm_l0,
                int          imm_l1,
                int          imm_l2,
                int          imm_l3 ) {
  FE_AVX_INL_DECL   ( vx     );
  FE_AVX_INL_LD     ( vx, x  );
  FE_AVX_INL_PERMUTE( vx, vx, imm_l0, imm_l1, imm_l2, imm_l3 );
  FE_AVX_INL_ST     ( z,  vx );
  return z;
}

static inline long *
fe_avx_copy( long *       z,
             long const * x ) {
  FE_AVX_INL_DECL( vx     );
  FE_AVX_INL_LD  ( vx, x  );
  FE_AVX_INL_ST  ( z,  vx );
  return z;
}

static inline long *
fe_avx_add( long *       z,
            long const * x,
            long const * y ) {
  FE_AVX_INL_DECL( vx         );
  FE_AVX_INL_DECL( vy         );
  FE_AVX_INL_LD  ( vx, x      );
  FE_AVX_INL_LD  ( vy, y      );
  FE_AVX_INL_ADD ( vx, vx, vy );
  FE_AVX_INL_ST  ( z,  vx     );
  return z;
}

static inline long *
fe_avx_sub( long *       z,
            long const * x,
            long const * y ) {
  FE_AVX_INL_DECL( vx         );
  FE_AVX_INL_DECL( vy         );
  FE_AVX_INL_LD  ( vx, x      );
  FE_AVX_INL_LD  ( vy, y      );
  FE_AVX_INL_SUB ( vx, vx, vy );
  FE_AVX_INL_ST  ( z,  vx     );
  return z;
}

FD_FN_UNUSED static long * /* Don't even try to inline this due to instruction limits */
fe_avx_mul( long *       z,
            long const * x,
            long const * y ) {
  FE_AVX_INL_DECL( vx         );
  FE_AVX_INL_DECL( vy         );
  FE_AVX_INL_LD  ( vx, x      );
  FE_AVX_INL_LD  ( vy, y      );
  FE_AVX_INL_MUL ( vx, vx, vy );
  FE_AVX_INL_ST  ( z,  vx     );
  return z;
}

FD_FN_UNUSED static long * /* Don't even try to inline this due to instruction limits */
fe_avx_sqn( long *       z,
            long const * x,
            int          na,
            int          nb,
            int          nc,
            int          nd ) {
  FE_AVX_INL_DECL( vx     );
  FE_AVX_INL_LD  ( vx, x  );
  FE_AVX_INL_SQN ( vx, vx, na,nb,nc,nd );
  FE_AVX_INL_ST  ( z,  vx );
  return z;
}

FD_FN_UNUSED static long * /* Don't even try to inline this due to instruction limits */
fe_avx_sq( long *       z,
           long const * x ) {
  FE_AVX_INL_DECL( vx     );
  FE_AVX_INL_LD  ( vx, x  );
  FE_AVX_INL_SQ  ( vx, vx );
  FE_AVX_INL_ST  ( z,  vx );
  return z;
}

static inline long *
fe_avx_sq_iter( long *       z,
                long const * x,
                ulong        n ) {
  if( !n ) fe_avx_copy( z, x );
  else {
    fe_avx_sq( z, x );
    for( n--; n; n-- ) fe_avx_sq( z, z );
  }
  return z;
}

static inline long *
fe_avx_pow22523( long *       h,
                 long const * f ) {
  long t0[ 40 ] __attribute__((aligned(64)));
  long t1[ 40 ] __attribute__((aligned(64)));
  long t2[ 40 ] __attribute__((aligned(64)));
  fe_avx_sq     ( t0, f         );
  fe_avx_sq_iter( t1, t0, 2UL   );
  fe_avx_mul    ( t1, f,  t1    );
  fe_avx_mul    ( t0, t0, t1    );
  fe_avx_sq     ( t0, t0        );
  fe_avx_mul    ( t0, t1, t0    );
  fe_avx_sq_iter( t1, t0, 5UL   );
  fe_avx_mul    ( t0, t1, t0    );
  fe_avx_sq_iter( t1, t0, 10UL  );
  fe_avx_mul    ( t1, t1, t0    );
  fe_avx_sq_iter( t2, t1, 20UL  );
  fe_avx_mul    ( t1, t2, t1    );
  fe_avx_sq_iter( t1, t1, 10UL  );
  fe_avx_mul    ( t0, t1, t0    );
  fe_avx_sq_iter( t1, t0, 50UL  );
  fe_avx_mul    ( t1, t1, t0    );
  fe_avx_sq_iter( t2, t1, 100UL );
  fe_avx_mul    ( t1, t2, t1    );
  fe_avx_sq_iter( t1, t1, 50UL  );
  fe_avx_mul    ( t0, t1, t0    );
  fe_avx_sq_iter( t0, t0, 2UL   );
  fe_avx_mul    ( h,  t0, f     );
  return h;
}

static inline long *
fe_avx_lane_select( long *       z,
                    long const * x,
                    int          c0,
                    int          c1,
                    int          c2,
                    int          c3 ) {
  FE_AVX_INL_DECL       ( vx     );
  FE_AVX_INL_LD         ( vx, x  );
  FE_AVX_INL_LANE_SELECT( vx, vx, c0, c1, c2, c3 );
  FE_AVX_INL_ST         ( z,  vx );
  return z;
}

static inline long *
fe_avx_dbl_mix( long *       h,
                long const * f ) {
  FE_AVX_INL_DECL   ( vf     );
  FE_AVX_INL_LD     ( vf, f  );
  FE_AVX_INL_DBL_MIX( vf, vf );
  FE_AVX_INL_ST     ( h,  vf );
  return h;
}

static inline long *
fe_avx_sub_mix( long *       h,
                long const * f ) {
  FE_AVX_INL_DECL   ( vf     );
  FE_AVX_INL_LD     ( vf, f  );
  FE_AVX_INL_SUB_MIX( vf, vf );
  FE_AVX_INL_ST     ( h,  vf );
  return h;
}

static inline long *
fe_avx_subadd_12( long *       h,
                  long const * f ) {
  FE_AVX_INL_DECL     ( vf     );
  FE_AVX_INL_LD       ( vf, f  );
  FE_AVX_INL_SUBADD_12( vf, vf );
  FE_AVX_INL_ST       ( h,  vf );
  return h;
}

FD_PROTOTYPES_END

