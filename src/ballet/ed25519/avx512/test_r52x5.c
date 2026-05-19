#include "../../fd_ballet.h"
#include "../fd_curve25519.h"

static void
fd_f25519_rand_canonical( fd_f25519_t * x,
                          fd_rng_t *    rng ) {
  x->el = wwl( (long)(fd_rng_ulong( rng ) & FD_F25519_LIMB_MASK),
               (long)(fd_rng_ulong( rng ) & FD_F25519_LIMB_MASK),
               (long)(fd_rng_ulong( rng ) & FD_F25519_LIMB_MASK),
               (long)(fd_rng_ulong( rng ) & FD_F25519_LIMB_MASK),
               (long)(fd_rng_ulong( rng ) & FD_F25519_LIMB_MASK),
               0L, 0L, 0L );
}

static void
fd_f25519_rand_loose( fd_f25519_t * x,
                      fd_rng_t *    rng ) {
  x->el = wwl( (long)(fd_rng_ulong( rng ) & ((1UL<<54)-1UL)),
               (long)(fd_rng_ulong( rng ) & ((1UL<<54)-1UL)),
               (long)(fd_rng_ulong( rng ) & ((1UL<<54)-1UL)),
               (long)(fd_rng_ulong( rng ) & ((1UL<<54)-1UL)),
               (long)(fd_rng_ulong( rng ) & ((1UL<<54)-1UL)),
               0L, 0L, 0L );
}

static void
fd_f25519_reduce_ref( fd_f25519_t *       r,
                      fd_f25519_t const * x ) {
  ulong h[5];
  fd_f25519_reduce( h, x->el );
  r->el = wwl( (long)h[0], (long)h[1], (long)h[2], (long)h[3], (long)h[4], 0L, 0L, 0L );
}

static int
fd_f25519_eq_limbs( fd_f25519_t const * x,
                    fd_f25519_t const * y ) {
  long xl[8] __attribute__((aligned(FD_F25519_ALIGN)));
  long yl[8] __attribute__((aligned(FD_F25519_ALIGN)));
  wwl_st( xl, x->el );
  wwl_st( yl, y->el );
  return (xl[0]==yl[0]) & (xl[1]==yl[1]) & (xl[2]==yl[2]) &
         (xl[3]==yl[3]) & (xl[4]==yl[4]);
}

static void
fd_f25519_mul_const_ref( fd_f25519_t *       r,
                         fd_f25519_t const * x,
                         ulong               c ) {
  fd_f25519_t k[1];
  k->el = wwl( (long)c, 0L, 0L, 0L, 0L, 0L, 0L, 0L );
  fd_f25519_mul( r, x, k );
}

#define FD_TEST_QUAD_EQ_LIMBS( Q, x, y, z, t ) do {                       \
    fd_f25519_t _x[1], _y[1], _z[1], _t[1];                               \
    FD_R52X5_QUAD_UNPACK( _x->el, _y->el, _z->el, _t->el, Q );            \
    FD_TEST( fd_f25519_eq_limbs( _x, (x) ) );                             \
    FD_TEST( fd_f25519_eq_limbs( _y, (y) ) );                             \
    FD_TEST( fd_f25519_eq_limbs( _z, (z) ) );                             \
    FD_TEST( fd_f25519_eq_limbs( _t, (t) ) );                             \
  } while(0)

#define FD_TEST_QUAD_EQ( Q, x, y, z, t ) do {                             \
    fd_f25519_t _x[1], _y[1], _z[1], _t[1];                               \
    FD_R52X5_QUAD_UNPACK( _x->el, _y->el, _z->el, _t->el, Q );            \
    FD_TEST( fd_f25519_eq( _x, (x) ) );                                   \
    FD_TEST( fd_f25519_eq( _y, (y) ) );                                   \
    FD_TEST( fd_f25519_eq( _z, (z) ) );                                   \
    FD_TEST( fd_f25519_eq( _t, (t) ) );                                   \
  } while(0)

#define FD_TEST_QUAD_REDUCED_EQ( Q, x, y, z, t ) do {                     \
    FD_R52X5_QUAD_DECL( _red );                                           \
    FD_R52X5_QUAD_REDUCE( _red, Q );                                      \
    fd_f25519_t _x[1], _y[1], _z[1], _t[1];                               \
    FD_R52X5_QUAD_UNPACK( _x->el, _y->el, _z->el, _t->el, _red );         \
    FD_TEST( fd_f25519_eq( _x, (x) ) );                                   \
    FD_TEST( fd_f25519_eq( _y, (y) ) );                                   \
    FD_TEST( fd_f25519_eq( _z, (z) ) );                                   \
    FD_TEST( fd_f25519_eq( _t, (t) ) );                                   \
  } while(0)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, 10000000UL );
  ulong warm_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--warm-max", NULL, 100UL      );
  ulong test_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--test-max", NULL, iter_max<131072UL ? iter_max : 131072UL );

  FD_LOG_NOTICE(( "Testing with --iter-max %lu --warm-max %lu --test-max %lu", iter_max, warm_max, test_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing quad inlines" ));

  for( ulong rem=test_max; rem; rem-- ) {
    fd_f25519_t x0[1], x1[1], x2[1], x3[1];
    fd_f25519_t y0[1], y1[1], y2[1], y3[1];
    fd_f25519_t z0[1], z1[1], z2[1], z3[1];
    fd_f25519_rand_canonical( x0, rng ); fd_f25519_rand_canonical( x1, rng );
    fd_f25519_rand_canonical( x2, rng ); fd_f25519_rand_canonical( x3, rng );
    fd_f25519_rand_canonical( y0, rng ); fd_f25519_rand_canonical( y1, rng );
    fd_f25519_rand_canonical( y2, rng ); fd_f25519_rand_canonical( y3, rng );

    FD_R52X5_QUAD_DECL( X ); FD_R52X5_QUAD_PACK( X, x0->el, x1->el, x2->el, x3->el );
    FD_R52X5_QUAD_DECL( Y ); FD_R52X5_QUAD_PACK( Y, y0->el, y1->el, y2->el, y3->el );
    FD_R52X5_QUAD_DECL( Z );

    FD_R52X5_QUAD_MOV( Z, Y );
    FD_TEST_QUAD_EQ_LIMBS( Z, y0, y1, y2, y3 );

    FD_R52X5_QUAD_ZERO( Z );
    FD_TEST_QUAD_EQ_LIMBS( Z, fd_f25519_zero, fd_f25519_zero, fd_f25519_zero, fd_f25519_zero );

    FD_R52X5_QUAD_PACK( Z, x0->el, x1->el, x2->el, x3->el );
    FD_TEST_QUAD_EQ_LIMBS( Z, x0, x1, x2, x3 );

    FD_R52X5_QUAD_PERMUTE( Z, 1,2,3,0, X );
    FD_TEST_QUAD_EQ_LIMBS( Z, x1, x2, x3, x0 );

    FD_R52X5_QUAD_PERMUTE( Z, 3,1,0,2, X );
    FD_TEST_QUAD_EQ_LIMBS( Z, x3, x1, x0, x2 );

    FD_R52X5_QUAD_LANE_IF( Z, 0,1,0,1, Y, X );
    FD_TEST_QUAD_EQ_LIMBS( Z, x0, y1, x2, y3 );

    fd_f25519_add_nr( z0, x0, y0 ); fd_f25519_add_nr( z1, x1, y1 );
    fd_f25519_add_nr( z2, x2, y2 ); fd_f25519_add_nr( z3, x3, y3 );
    FD_R52X5_QUAD_ADD_FAST( Z, X, Y );
    FD_TEST_QUAD_EQ_LIMBS( Z, z0, z1, z2, z3 );

    fd_f25519_rand_loose( x0, rng ); fd_f25519_rand_loose( x1, rng );
    fd_f25519_rand_loose( x2, rng ); fd_f25519_rand_loose( x3, rng );
    FD_R52X5_QUAD_PACK( X, x0->el, x1->el, x2->el, x3->el );
    fd_f25519_reduce_ref( z0, x0 ); fd_f25519_reduce_ref( z1, x1 );
    fd_f25519_reduce_ref( z2, x2 ); fd_f25519_reduce_ref( z3, x3 );
    FD_R52X5_QUAD_REDUCE( Z, X );
    FD_TEST_QUAD_EQ_LIMBS( Z, z0, z1, z2, z3 );

    fd_f25519_rand_canonical( x0, rng ); fd_f25519_rand_canonical( x1, rng );
    fd_f25519_rand_canonical( x2, rng ); fd_f25519_rand_canonical( x3, rng );
    fd_f25519_rand_canonical( y0, rng ); fd_f25519_rand_canonical( y1, rng );
    fd_f25519_rand_canonical( y2, rng ); fd_f25519_rand_canonical( y3, rng );
    FD_R52X5_QUAD_PACK( X, x0->el, x1->el, x2->el, x3->el );
    FD_R52X5_QUAD_PACK( Y, y0->el, y1->el, y2->el, y3->el );

    fd_f25519_neg( z0, x0 ); fd_f25519_neg( z1, x1 );
    fd_f25519_neg( z2, x2 ); fd_f25519_neg( z3, x3 );
    FD_R52X5_QUAD_NEGATE_LAZY( Z, X );
    FD_TEST_QUAD_REDUCED_EQ( Z, z0, z1, z2, z3 );

    fd_f25519_sub( z0, x1, x0 ); fd_f25519_add( z1, x0, x1 );
    fd_f25519_sub( z2, x3, x2 ); fd_f25519_add( z3, x2, x3 );
    FD_R52X5_QUAD_DIFF_SUM( Z, X );
    FD_TEST_QUAD_REDUCED_EQ( Z, z0, z1, z2, z3 );

    wv_t k = wv( 121666, 121665, 2*121666, 2*121665 );
    fd_f25519_mul_const_ref( z0, x0, 121666UL   );
    fd_f25519_mul_const_ref( z1, x1, 121665UL   );
    fd_f25519_mul_const_ref( z2, x2, 2UL*121666UL );
    fd_f25519_mul_const_ref( z3, x3, 2UL*121665UL );
    FD_R52X5_QUAD_MUL_CONSTANT( Z, X, k );
    FD_TEST_QUAD_REDUCED_EQ( Z, z0, z1, z2, z3 );

    fd_f25519_mul( z0, x0, y0 ); fd_f25519_mul( z1, x1, y1 );
    fd_f25519_mul( z2, x2, y2 ); fd_f25519_mul( z3, x3, y3 );
    FD_R52X5_QUAD_MUL_FAST( Z, X, Y );
    FD_TEST_QUAD_REDUCED_EQ( Z, z0, z1, z2, z3 );

    fd_f25519_sqr( z0, x0 ); fd_f25519_sqr( z1, x1 );
    fd_f25519_sqr( z2, x2 ); fd_f25519_sqr( z3, x3 );
    FD_R52X5_QUAD_SQR_FAST( Z, X );
    FD_TEST_QUAD_REDUCED_EQ( Z, z0, z1, z2, z3 );
  }

  FD_LOG_NOTICE(( "Testing group helpers" ));

  do {
    fd_ed25519_point_t zero[1], base[1], dbl[1], add[1], via_table[1], table[1];

    FD_R52X5_GE_ZERO( zero->P );
    FD_TEST( fd_ed25519_point_is_zero( zero ) );

    fd_ed25519_point_set( base, fd_ed25519_base_point );
    FD_R52X5_GE_DBL( dbl->P, base->P );
    FD_R52X5_GE_ADD( add->P, base->P, base->P );
    FD_TEST( FD_R52X5_GE_IS_EQ( dbl->P, add->P ) );

    fd_ed25519_point_set( table, base );
    fd_curve25519_into_precomputed( table );
    fd_ed25519_point_t tmp[2];
    FD_R52X5_GE_ADD_TABLE( via_table->P, base->P, table->P, tmp[0].P, tmp[1].P );
    FD_TEST( FD_R52X5_GE_IS_EQ( via_table->P, add->P ) );

    uchar buf[32];
    fd_ed25519_point_t dec0[1], dec1[1];
    fd_ed25519_affine_tobytes( buf, fd_ed25519_base_point );
    FD_TEST( !FD_R52X5_GE_DECODE2( dec0->P, buf, dec1->P, buf ) );
    FD_TEST( FD_R52X5_GE_IS_EQ( dec0->P, base->P ) );
    FD_TEST( FD_R52X5_GE_IS_EQ( dec1->P, base->P ) );

    fd_memset( buf, 0, 32UL );
    buf[0] = 2U;
    FD_TEST( FD_R52X5_GE_DECODE2( dec0->P, buf, dec1->P, buf )==-1 );
    FD_TEST( fd_ed25519_point_is_zero( dec1 ) );
  } while(0);

  FD_LOG_NOTICE(( "Benchmarking" ));

  do {
    fd_f25519_t x0[1], x1[1], x2[1], x3[1];
    fd_f25519_t y0[1], y1[1], y2[1], y3[1];
    fd_f25519_rand_canonical( x0, rng ); fd_f25519_rand_canonical( x1, rng );
    fd_f25519_rand_canonical( x2, rng ); fd_f25519_rand_canonical( x3, rng );
    fd_f25519_rand_canonical( y0, rng ); fd_f25519_rand_canonical( y1, rng );
    fd_f25519_rand_canonical( y2, rng ); fd_f25519_rand_canonical( y3, rng );

#   define BENCH(op) do {                                                     \
      for( ulong rem=warm_max; rem; rem-- ) op;                               \
      long dt = -fd_log_wallclock();                                          \
      for( ulong rem=iter_max; rem; rem-- ) op;                               \
      dt += fd_log_wallclock();                                               \
      FD_LOG_NOTICE(( "%-77s: %9.3f ns", #op, (double)dt/(double)iter_max )); \
    } while(0)

    FD_R52X5_QUAD_DECL( X ); FD_R52X5_QUAD_PACK( X, x0->el, x1->el, x2->el, x3->el );
    FD_R52X5_QUAD_DECL( Y ); FD_R52X5_QUAD_PACK( Y, y0->el, y1->el, y2->el, y3->el );

    BENCH( FD_R52X5_QUAD_PACK( X, x0->el, x1->el, x2->el, x3->el ); FD_R52X5_QUAD_UNPACK( x0->el, x1->el, x2->el, x3->el, X ) );
    BENCH( FD_R52X5_QUAD_PERMUTE( X, 1,2,3,0, X ) );
    BENCH( FD_R52X5_QUAD_LANE_IF( X, 0,0,1,1, Y, X ) );
    BENCH( FD_R52X5_QUAD_ADD_FAST( X, X, Y ) );
    BENCH( FD_R52X5_QUAD_REDUCE( X, X ) );
    BENCH( FD_R52X5_QUAD_NEGATE_LAZY( X, X ) );
    BENCH( FD_R52X5_QUAD_DIFF_SUM( X, X ) );
    BENCH( FD_R52X5_QUAD_MUL_CONSTANT( X, X, wv( 121666, 121666, 2*121666, 2*121665 ) ) );
    BENCH( FD_R52X5_QUAD_MUL_FAST( X, X, Y ) );
    BENCH( FD_R52X5_QUAD_SQR_FAST( X, X ) );

    BENCH( FD_R52X5_GE_ADD( X, X, Y ) );
    BENCH( FD_R52X5_GE_DBL( X, X ) );

    /* Prevent compiler from optimizing away */
    FD_COMPILER_UNPREDICTABLE( X0 ); FD_COMPILER_UNPREDICTABLE( X1 );
    FD_COMPILER_UNPREDICTABLE( X2 ); FD_COMPILER_UNPREDICTABLE( X3 );
    FD_COMPILER_UNPREDICTABLE( X4 );
  } while(0);

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
