#include "../fd_util.h"

/* FIXME: PROBABLY SHOULD TEST UNCAUGHT EXCEPTIONS */

char const * _argv[] = { "Hey", "You", NULL };

#if !defined (FD_HAS_ASAN) || !FD_HAS_ASAN
static void
test_stack( void ) {
  ulong stack0 = (ulong)fd_tile_stack0();
  if( !stack0 ) {
    FD_TEST( !fd_tile_stack1        () );
    FD_TEST( !fd_tile_stack_sz      () );
    FD_TEST( !fd_tile_stack_est_free() );
    FD_TEST( !fd_tile_stack_est_used() );
  } else {
    ulong stack1         = (ulong)fd_tile_stack1();  FD_TEST( stack1>stack0             );
    ulong stack_sz       = fd_tile_stack_sz();       FD_TEST( stack_sz==(stack1-stack0) );
    ulong stack_est_free = fd_tile_stack_est_free(); FD_TEST( stack_est_free<=stack_sz  );
    ulong stack_est_used = fd_tile_stack_est_used(); FD_TEST( stack_est_used<=stack_sz  );

    /* We should have more free than used for this test so this really
       just checks if the grows from high to low assumption is correct */

    FD_TEST( stack_est_free > stack_est_used );

    /* Paranoia ... since free and used est aren't measured at the same
       point in time above, we only test for approximate equality (they
       are probably the same at this point unless the compiler is being
       insanely weird). */

    ulong stack_est = stack_est_free + stack_est_used;
    FD_TEST( (stack_sz-64UL)<=stack_est && stack_est<=(stack_sz+64UL) );

    ulong stack_mem[1];
    FD_VOLATILE( stack_mem[0] ) = (uchar)1; /* Paranoia */
    ulong stack_addr = (ulong)stack_mem;
    FD_TEST( (stack0<=stack_addr) & (stack_addr<stack1) );

    FD_LOG_NOTICE(( "testing stack" ));
    for( ulong stack=stack0; stack<stack1; stack++ ) FD_VOLATILE_CONST( *(uchar const *)stack );
  }
}
#else
static void
test_stack( void ) {}
#endif

int
tile_main( int     argc,
           char ** argv ) {
  FD_LOG_NOTICE(( "cnt %lu", fd_tile_cnt() )); FD_TEST( 0UL<fd_tile_cnt() ); FD_TEST( fd_tile_cnt()<=FD_TILE_MAX );
  FD_LOG_NOTICE(( "id0 %lu", fd_tile_id0() ));
  FD_LOG_NOTICE(( "id1 %lu", fd_tile_id1() )); FD_TEST( fd_tile_cnt()==(fd_tile_id1()-fd_tile_id0()) );
  FD_LOG_NOTICE(( "id  %lu", fd_tile_id () )); FD_TEST( fd_tile_id()==fd_tile_id0()+fd_tile_idx() );
  FD_LOG_NOTICE(( "idx %lu", fd_tile_idx() )); FD_TEST( fd_tile_idx()<fd_tile_cnt() );
  fd_log_flush();

  test_stack();

  FD_TEST( fd_tile_id()==fd_log_thread_id() );

  FD_TEST( argc==(int)fd_tile_idx() );
  FD_TEST( argv==(char **)_argv );

  FD_TEST( !fd_tile_exec_new( 0UL,           tile_main, argc, argv ) ); /* Can't dispatch to tile 0 */
  FD_TEST( !fd_tile_exec_new( fd_tile_idx(), tile_main, argc, argv ) ); /* Can't dispatch to self */

  if( fd_tile_idx()==fd_tile_cnt()-2UL ) { /* Test tile-to-tile dispatch */
    ulong idx = fd_tile_idx()+1UL;
    fd_tile_exec_t * exec = fd_tile_exec_new( idx, tile_main, argc+1, argv );

    FD_TEST( fd_tile_exec      (               idx )==exec );
    FD_TEST( fd_tile_exec_by_id( fd_tile_id0()+idx )==exec );

    FD_TEST( fd_tile_exec_idx ( exec )==idx       );
    FD_TEST( fd_tile_exec_task( exec )==tile_main );
    FD_TEST( fd_tile_exec_argc( exec )==argc+1    );
    FD_TEST( fd_tile_exec_argv( exec )==argv      );

    int done = fd_tile_exec_done( exec );
    FD_TEST( 0<=done && done<=1 );

    int          ret;
    char const * fail = fd_tile_exec_delete( exec, &ret );
    FD_TEST( ret==argc+1 );
    FD_TEST( !fail );
  }

  return argc;
}

FD_STATIC_ASSERT( FD_TILE_MAX>0UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong tile_cnt = fd_tile_cnt();

  FD_LOG_NOTICE(( "cnt %lu", tile_cnt      )); FD_TEST( tile_cnt>0UL ); FD_TEST( tile_cnt<=FD_TILE_MAX );
  FD_LOG_NOTICE(( "id0 %lu", fd_tile_id0() ));
  FD_LOG_NOTICE(( "id1 %lu", fd_tile_id1() )); FD_TEST( tile_cnt==(fd_tile_id1()-fd_tile_id0()) );
  FD_LOG_NOTICE(( "id  %lu", fd_tile_id () )); FD_TEST( fd_tile_id()==fd_tile_id0() );
  FD_LOG_NOTICE(( "idx %lu", fd_tile_idx() )); FD_TEST( fd_tile_idx()==0UL );
  fd_log_flush();

  test_stack();

# if FD_HAS_HOSTED
  ulong cpu_cnt = fd_shmem_cpu_cnt();

  ulong cpu_seen = 0UL;
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    ulong cpu_id = fd_tile_cpu_id( tile_idx );
    FD_TEST( (cpu_id<cpu_cnt) | (cpu_id==(ULONG_MAX-1UL)) );
    if( cpu_id==(ULONG_MAX-1UL) ) FD_LOG_NOTICE(( "tile %lu -> floating", tile_idx ));
    else {
      FD_LOG_NOTICE(( "tile %lu -> cpu %lu", tile_idx, cpu_id ));
      if( FD_LIKELY( cpu_id<64UL ) ) {
        FD_TEST( !fd_ulong_extract_bit( cpu_seen, (int)cpu_id ) );
        cpu_seen = fd_ulong_set_bit( cpu_seen, (int)cpu_id );
      } else {
        static int warn = 0;
        if( !warn ) {
          FD_LOG_WARNING(( "Test can only fully validate fd_tile_cpu_id for cpus in [0,64)" ));
          warn = 1;
        }
      }
    }
  }
# endif

  fd_log_flush();

  FD_TEST( fd_tile_id()==fd_log_thread_id() );

  for( ulong idx=1UL; idx<tile_cnt-1UL; idx++ ) {
    int     argc = (int)idx;
    char ** argv = (char **)_argv;

    FD_TEST( !fd_tile_exec_new( 0UL, tile_main, argc, argv ) ); /* Can't dispatch to self or tile 0 */

    fd_tile_exec_t * exec = fd_tile_exec_new( idx, tile_main, argc, argv );

    FD_TEST( fd_tile_exec      (               idx )==exec );
    FD_TEST( fd_tile_exec_by_id( fd_tile_id0()+idx )==exec );

    FD_TEST( fd_tile_exec_idx ( exec )==idx       );
    FD_TEST( fd_tile_exec_task( exec )==tile_main );
    FD_TEST( fd_tile_exec_argc( exec )==argc      );
    FD_TEST( fd_tile_exec_argv( exec )==argv      );

    int done = fd_tile_exec_done( exec );
    FD_TEST( 0<=done && done<=1 );

    int          ret;
    char const * fail = fd_tile_exec_delete( exec, &ret );
    FD_TEST( ret==argc );
    FD_TEST( !fail );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

