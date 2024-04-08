#include "../fd_tango.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# if FD_HAS_DOUBLE

  for( ulong iter=0; iter<10; iter++ ) {
    double tau;
    double t0 = fd_tempo_wallclock_model( &tau );
    FD_TEST( ((0.< t0 ) & (t0 <=DBL_MAX)) );
    FD_TEST( ((0.<=tau) & (tau<=DBL_MAX)) );

    double tau_;
    double t0_ = fd_tempo_wallclock_model( &tau_ );
    FD_TEST( t0_ ==t0  );
    FD_TEST( tau_==tau );
    FD_LOG_NOTICE(( "wallclock:   min %8.3f ns   tau %8.2e ns", t0, tau ));
  }

  for( ulong iter=0; iter<10; iter++ ) {
    double tau;
    double t0 = fd_tempo_tickcount_model( &tau );
    FD_TEST( ((0.< t0 ) & (t0 <=DBL_MAX)) );
    FD_TEST( ((0.<=tau) & (tau<=DBL_MAX)) );

    double tau_;
    double t0_ = fd_tempo_tickcount_model( &tau_ );
    FD_TEST( t0_ ==t0  );
    FD_TEST( tau_==tau );

    FD_LOG_NOTICE(( "tickcount:   min %8.3f tick tau %8.2e tick", t0, tau ));
  }

  for( ulong iter=0; iter<10; iter++ ) {
    double rms;
    double avg = fd_tempo_tick_per_ns( &rms );
    FD_TEST( ((0.< avg) & (avg<=DBL_MAX)) );
    FD_TEST( ((0.<=rms) & (rms<=DBL_MAX)) );

    double rms_;
    double avg_ = fd_tempo_tick_per_ns( &rms_ );
    FD_TEST( avg_==avg );
    FD_TEST( rms_==rms );
    FD_LOG_NOTICE(( "tick_per_ns: avg %8.3f ghz  rms %8.2e ghz", avg, rms ));
  }

# endif

  long now;
  long toc;
  long jot = fd_tempo_observe_pair( &now, &toc );

  for( ulong iter=0; iter<8; iter++ ) {

    long then;
    long tic;
    long jit = fd_tempo_observe_pair( &then, &tic );

    FD_TEST( jot>=0L       );
    FD_TEST( jit>=0L       );
    FD_TEST( (then-now)>0L );
    FD_TEST( (tic -toc)>0L );

    jot = fd_tempo_observe_pair( &now, &toc );

    FD_TEST( jit>=0L       );
    FD_TEST( jot>=0L       );
    FD_TEST( (now-then)>0L );
    FD_TEST( (toc-tic )>0L );

    FD_LOG_NOTICE(( "observe_pair\n\t"
                    "then %20li ns tic %20li tick jit %20li tick\n\t"
                    "now  %20li ns toc %20li tick jot %20li tick\n\t"
                    "diff %20li ns     %20li tick     %20li tick",
                    then, tic, jit, now, toc, jot, now-then, toc-tic, jot-jit ));
  }

  for( ulong cr_max=0UL; cr_max<10UL; cr_max++ ) FD_TEST( fd_tempo_lazy_default( cr_max )==(long)(1UL+((9UL*cr_max)/4UL)) );
  FD_TEST( fd_tempo_lazy_default( 954437175UL )==2147483644L );
  FD_TEST( fd_tempo_lazy_default( 954437176UL )==2147483647L );
  FD_TEST( fd_tempo_lazy_default( 954437177UL )==2147483647L );
  FD_TEST( fd_tempo_lazy_default( ULONG_MAX   )==2147483647L );

//FD_TEST( !fd_tempo_async_min(   0L,     1UL, 1.f ) );
//FD_TEST( !fd_tempo_async_min(   1L,     0UL, 1.f ) );
//FD_TEST( !fd_tempo_async_min(   1L,     1UL, 0.f ) );
//FD_TEST( !fd_tempo_async_min( 100L, 10000UL, 1.f ) );
  FD_TEST( fd_ulong_is_pow2( fd_tempo_async_min( 100000L, 1UL, 1.f ) ) );

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong async_min = 1UL << (int)(fd_rng_uint( rng ) & 31U );
    ulong async_rem = fd_tempo_async_reload( rng, async_min );
    FD_TEST( async_min<=async_rem     );
    FD_TEST( async_rem< 2UL*async_min );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

