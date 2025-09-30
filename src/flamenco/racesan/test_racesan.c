#include "fd_racesan.h"
#include "fd_racesan_async.h"
#include "fd_racesan_target.h"
#include "../../util/fd_util.h"

#if FD_HAS_RACESAN

static void
cas_inc( uint * p ) {
  for(;;) {
    uint v = FD_VOLATILE_CONST( *p );
    fd_racesan_hook( "cas_inc:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( p, v, v+1U ) ) ) break;
  }
}

static void
inject_inc( void * ctx,
            ulong  name_hash ) {
  (void)name_hash;
  uint * p = ctx;
  if( FD_VOLATILE_CONST( *p )==0U ) FD_VOLATILE( *p ) = 1U;
}

static void
test_racesan_inject( void ) {
  uint ctx = 0U;
  fd_racesan_t racesan[1];
  FD_TEST( fd_racesan_new( racesan, &ctx ) );

  fd_racesan_inject( racesan, "cas_inc:post_load", inject_inc );
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    cas_inc( &ctx );
  }
  FD_RACESAN_INJECT_END;

  FD_TEST( FD_VOLATILE_CONST( ctx )==2U );
  fd_racesan_delete( racesan );
}

static void
async_cas_inc( void * ctx ) {
  uint * seq = ctx;
  cas_inc( seq );
}

static void
test_racesan_async( void ) {
  uint seq = 0U;

  fd_racesan_async_t async[1];
  fd_racesan_async_new( async, async_cas_inc, &seq );

  FD_TEST( fd_racesan_async_step( async )==1 );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );

  FD_VOLATILE( seq )++;
  FD_TEST( fd_racesan_async_step( async )==1 );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );
  FD_TEST( fd_racesan_async_step( async )==1 );

  FD_TEST( fd_racesan_async_step( async )==0 );
  FD_TEST( fd_racesan_async_step( async )==0 );

  fd_racesan_async_delete( async );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_racesan_async();
  test_racesan_inject();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else /* !FD_HAS_RACESAN */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "skip: unit test requires FD_HAS_RACESAN" ));
  fd_halt();
  return 0;
}

#endif
