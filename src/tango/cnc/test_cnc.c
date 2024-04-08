#include "../fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_ATOMIC

FD_STATIC_ASSERT( FD_CNC_ALIGN          ==128UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_FOOTPRINT( 0UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_FOOTPRINT(64UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_FOOTPRINT(65UL)==256UL, unit_test );

FD_STATIC_ASSERT( FD_CNC_APP_ALIGN==64UL, unit_test );

FD_STATIC_ASSERT( FD_CNC_SIGNAL_RUN ==0UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_SIGNAL_BOOT==1UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_SIGNAL_FAIL==2UL, unit_test );
FD_STATIC_ASSERT( FD_CNC_SIGNAL_HALT==3UL, unit_test );

FD_STATIC_ASSERT( FD_CNC_SUCCESS  == 0, unit_test );
FD_STATIC_ASSERT( FD_CNC_ERR_UNSUP==-1, unit_test );
FD_STATIC_ASSERT( FD_CNC_ERR_INVAL==-2, unit_test );
FD_STATIC_ASSERT( FD_CNC_ERR_AGAIN==-3, unit_test );
FD_STATIC_ASSERT( FD_CNC_ERR_FAIL ==-4, unit_test );

#define APP_MIN (32UL)
#define APP_MAX (192UL)
uchar __attribute__((aligned(FD_CNC_ALIGN))) shmem[ FD_CNC_FOOTPRINT( APP_MAX ) ];

#define USER_ACK  4UL
#define USER_GAME 5UL
#define USER_PING 6UL
#define USER_PONG 7UL

static int
app_main( int     argc,
          char ** argv ) {

  /* Boot up the app thread (we are in the BOOT state) */

  FD_TEST( !argc );
  fd_cnc_t * cnc = fd_cnc_join( (void *)argv );
  FD_TEST( cnc );
  FD_TEST( fd_cnc_signal_query( cnc )==FD_CNC_SIGNAL_BOOT );

  ulong * app = (ulong *)fd_cnc_app_laddr( cnc );
  ulong const * app_const = (ulong const *)fd_cnc_app_laddr_const( cnc );
  FD_TEST( (ulong)app==(ulong)app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)app, FD_CNC_APP_ALIGN ) );

  /* Signal we are doing booting and start running */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );

  /* App thread run loop (we are in the RUN state) */

  for(;;) {

    /* Sporadically heartbeat and check if we have a signal to process */

    long now = fd_log_wallclock();
    fd_cnc_heartbeat( cnc, now );
    ulong signal = fd_cnc_signal_query( cnc );
    if( FD_UNLIKELY( signal!=FD_CNC_SIGNAL_RUN ) ) {
      if     ( signal==FD_CNC_SIGNAL_HALT ) break; /* Got HALT signal ... exit run loop */
      else if( signal==USER_ACK ) fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN ); /* Got ACK signal ... clear it to ack */
      else if( signal==USER_GAME ) { /* Got GAME signal */

        /* Serve ball and wait for return */
        ulong ball = FD_VOLATILE_CONST( app[0] );
        FD_VOLATILE( app[1] ) = ball+1UL;
        fd_cnc_signal( cnc, USER_PING );
        FD_TEST( fd_cnc_wait( cnc, USER_PING, (long)30e9, &now )==USER_PONG );

        /* Test legal game, return ball and finish game */
        FD_TEST( FD_VOLATILE_CONST( app[0] )==ball     );
        FD_TEST( FD_VOLATILE_CONST( app[1] )==ball+1UL );
        FD_TEST( FD_VOLATILE_CONST( app[2] )==ball+2UL );
        FD_VOLATILE( app[3] ) = ball+3UL;
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );

      } else FD_LOG_ERR(( "Unexpected cnc signal %lu", signal ));
    }

    /* Dummy run operations */

    FD_YIELD();
  }

  /* Halt the app thread (we are in HALT state) */
  
  /* Dummy halt operations */

  FD_YIELD();

  /* Signal we are doing halting and it was a clean halt before
     terminating execution. */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_TEST( fd_cnc_leave( cnc )==(void *)argv );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong app_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--app-sz", NULL,  192UL );
  ulong type   = fd_env_strip_cmdline_ulong( &argc, &argv, "--type",   NULL, 1234UL );

  if( FD_UNLIKELY( app_sz<APP_MIN     ) ) FD_LOG_ERR(( "app_sz should be at least %lu for this unit test", APP_MIN ));
  if( FD_UNLIKELY( app_sz>APP_MAX     ) ) FD_LOG_ERR(( "increase APP_MAX for this app_sz"  ));
  if( FD_UNLIKELY( fd_tile_cnt()!=2UL ) ) FD_LOG_ERR(( "this unit-test requires two tiles" ));

  FD_TEST( !fd_cnc_footprint( ULONG_MAX ) );

  FD_TEST( fd_cnc_align()            ==FD_CNC_ALIGN               );
  FD_TEST( fd_cnc_footprint( app_sz )==FD_CNC_FOOTPRINT( app_sz ) );

  long now = fd_log_wallclock();
  void * shcnc = fd_cnc_new( shmem, app_sz, type, now ); FD_TEST( shcnc );
  fd_cnc_t * cnc = fd_cnc_join( shcnc );                 FD_TEST( cnc );

  FD_TEST( fd_cnc_app_sz( cnc )==app_sz );
  ulong *       app       = (ulong       *)fd_cnc_app_laddr( cnc );
  ulong const * app_const = (ulong const *)fd_cnc_app_laddr_const( cnc );
  FD_TEST( (ulong)app==(ulong)app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)app, FD_CNC_APP_ALIGN ) );

  FD_TEST( fd_cnc_type           ( cnc )==type               );
  FD_TEST( fd_cnc_heartbeat0     ( cnc )==now                );
  FD_TEST( fd_cnc_heartbeat_query( cnc )==now                );
  FD_TEST( fd_cnc_signal_query   ( cnc )==FD_CNC_SIGNAL_BOOT );

//FD_TEST( fd_cnc_open( cnc )==FD_CNC_ERR_AGAIN ); /* Should fail as app thread isn't running yet */

  FD_LOG_NOTICE(( "fd_cnc_strerror( FD_CNC_SUCCESS   ): %s", fd_cnc_strerror( FD_CNC_SUCCESS   ) ));
  FD_LOG_NOTICE(( "fd_cnc_strerror( FD_CNC_ERR_UNSUP ): %s", fd_cnc_strerror( FD_CNC_ERR_UNSUP ) ));
  FD_LOG_NOTICE(( "fd_cnc_strerror( FD_CNC_ERR_INVAL ): %s", fd_cnc_strerror( FD_CNC_ERR_INVAL ) ));
  FD_LOG_NOTICE(( "fd_cnc_strerror( FD_CNC_ERR_AGAIN ): %s", fd_cnc_strerror( FD_CNC_ERR_AGAIN ) ));
  FD_LOG_NOTICE(( "fd_cnc_strerror( FD_CNC_ERR_FAIL  ): %s", fd_cnc_strerror( FD_CNC_ERR_FAIL  ) ));
  FD_LOG_NOTICE(( "fd_cnc_strerror( 1                ): %s", fd_cnc_strerror( 1                ) ));

  char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
  FD_TEST( !strcmp( fd_cnc_signal_cstr( FD_CNC_SIGNAL_RUN,  buf ), "run"  ) );
  FD_TEST( !strcmp( fd_cnc_signal_cstr( FD_CNC_SIGNAL_BOOT, buf ), "boot" ) );
  FD_TEST( !strcmp( fd_cnc_signal_cstr( FD_CNC_SIGNAL_FAIL, buf ), "fail" ) );
  FD_TEST( !strcmp( fd_cnc_signal_cstr( FD_CNC_SIGNAL_HALT, buf ), "halt" ) );
  FD_TEST( !strcmp( fd_cnc_signal_cstr( 4UL,                buf ), "4"    ) );

  FD_TEST( fd_cstr_to_cnc_signal( "run"  )==FD_CNC_SIGNAL_RUN  );
  FD_TEST( fd_cstr_to_cnc_signal( "boot" )==FD_CNC_SIGNAL_BOOT );
  FD_TEST( fd_cstr_to_cnc_signal( "fail" )==FD_CNC_SIGNAL_FAIL );
  FD_TEST( fd_cstr_to_cnc_signal( "halt" )==FD_CNC_SIGNAL_HALT );
  FD_TEST( fd_cstr_to_cnc_signal( "4"    )==4UL                );

  /* Start up the app thread and wait to finish booting */

  fd_tile_exec_t * app_thread = fd_tile_exec_new( 1UL, app_main, 0, (char **)shcnc );
  FD_TEST( fd_cnc_wait( cnc, FD_CNC_SIGNAL_BOOT, (long)30e9, &now )==FD_CNC_SIGNAL_RUN );

  /* Start a command and control session with the app thread */

  FD_TEST( fd_cnc_open( cnc )==FD_CNC_SUCCESS   );
//FD_TEST( fd_cnc_open( cnc )==FD_CNC_ERR_AGAIN ); /* Should fail as we already have a session open */

  for( ulong iter=0UL; iter<32UL; iter++ ) {
    FD_LOG_NOTICE(( "Test %2lu (app thread heartbeat %li)", iter, fd_cnc_heartbeat_query( cnc ) ));
    
    /* Request ack */
    fd_cnc_signal( cnc, USER_ACK );
    FD_TEST( fd_cnc_wait( cnc, USER_ACK, (long)30e9, &now )==FD_CNC_SIGNAL_RUN );

    /* Request a game and wait for serve */
    ulong ball = fd_ulong_hash( iter );
    FD_VOLATILE( app[0] ) = ball;
    fd_cnc_signal( cnc, USER_GAME );
    FD_TEST( fd_cnc_wait( cnc, USER_GAME, (long)30e9, &now )==USER_PING );

    /* Test legal game, return the ball and wait for game to finish */
    FD_TEST( FD_VOLATILE_CONST( app[0] )==ball     );
    FD_TEST( FD_VOLATILE_CONST( app[1] )==ball+1UL );
    FD_VOLATILE( app[2] ) = ball+2UL;
    fd_cnc_signal( cnc, USER_PONG );

    /* Test legal game */
    FD_TEST( fd_cnc_wait( cnc, USER_PONG, (long)30e9, &now )==FD_CNC_SIGNAL_RUN );
    FD_TEST( FD_VOLATILE_CONST( app[0] )==ball     );
    FD_TEST( FD_VOLATILE_CONST( app[1] )==ball+1UL );
    FD_TEST( FD_VOLATILE_CONST( app[2] )==ball+2UL );
    FD_TEST( FD_VOLATILE_CONST( app[3] )==ball+3UL );

    FD_YIELD();
  }

  /* Tell the app thread to halt and wait for it to finish halting */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_HALT );
  FD_TEST( fd_cnc_wait( cnc, FD_CNC_SIGNAL_HALT, (long)30e9, &now )==FD_CNC_SIGNAL_BOOT );

  /* Finish command and control session with the app thread */

  fd_cnc_close( cnc );

//FD_TEST( fd_cnc_open( cnc )==FD_CNC_ERR_AGAIN ); /* Should fail as app thread isn't running yet */

  int ret;
  FD_TEST( !fd_tile_exec_delete( app_thread, &ret ) );
  FD_TEST( !ret );

  FD_TEST( fd_cnc_leave( cnc )==shcnc );
  FD_TEST( fd_cnc_delete( shcnc )==shmem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "skip: unit test requires FD_HAS_HOSTED and FD_HAS_ATOMIC capabilities" ));
  fd_halt();
  return 0;
}

#endif

