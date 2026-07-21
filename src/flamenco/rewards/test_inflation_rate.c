#include "fd_rewards.c"

/* The inflation rates must match Agave bit-for-bit: rustc never
   contracts FP expressions into FMAs, so validator() needs two
   independently rounded ops (see the volatile there). */

/* validator() without the intermediate rounding: one fused rounding. */
static double
validator_fused( fd_inflation_t const * inflation, double year ) {
  double t = total( inflation, year );
  if( !(year < inflation->foundation_term) ) return t;
  return fma( -inflation->foundation, t, t );
}

static ulong
dbl_bits( double x ) {
  ulong u; memcpy( &u, &x, sizeof(ulong) );
  return u;
}

/* noinline keeps pow() on the scalar libm path (a vectorized loop
   would call libmvec, which is allowed to differ by a few ulp). */

static __attribute__((noinline)) void
check_boundary_case( fd_inflation_t const * inflation,
                     double                 year,
                     ulong                  validator_bits ) {
  FD_TEST( dbl_bits( validator      ( inflation, year ) )==validator_bits );
  FD_TEST( dbl_bits( validator_fused( inflation, year ) )!=validator_bits );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_inflation_t const inflation = {
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  /* Volatile so the computation is not constant folded.  Exercised
     end-to-end by test-vectors block/edge_case_rounding.fix. */

  volatile double year_v = 0x1.ba9f11a7bf14fp-1;
  double year = year_v;

  FD_TEST( dbl_bits( total     ( &inflation, year ) )==0x3FB1CBAD5BFB1CF2UL );
  FD_TEST( dbl_bits( foundation( &inflation, year ) )==0x3F6C79155FF82E50UL );
  FD_TEST( dbl_bits( validator ( &inflation, year ) )==0x3FB0E7E4B0FB5B80UL );
  FD_TEST( dbl_bits( validator_fused( &inflation, year ) )==0x3FB0E7E4B0FB5B7FUL );

  /* More rounding-boundary years. */

  struct { double year; ulong validator_bits; } cases[] = {
    { 0x1.1df81a0020062p-2, 0x3FB297BB9ADACA4EUL },
    { 0x1.aa266d0534bddp-2, 0x3FB22F01D0EDD9C6UL },
    { 0x1.dc9d80aae00a3p-1, 0x3FB0B971E9C677DAUL },
    { 0x1.506f2da5cb528p+0, 0x3FAF6DBE0B59F0CAUL },
    { 0x1.222cb0f898f72p+2, 0x3FA29FB7A2EDCD64UL },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    volatile double case_year_v = cases[i].year;
    check_boundary_case( &inflation, case_year_v, cases[i].validator_bits );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
