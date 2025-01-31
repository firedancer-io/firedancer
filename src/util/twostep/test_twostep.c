#include "fd_twostep.h"

/* define broken mutex */
void
bad_mutex_lock( uint * mut ) {
  /* wait for mutex */
  while( *mut != 0 ) { }

  /* set mutex */
  *mut = 1;
}

/* define correct mutex */
void
good_mutex_lock( uint * mut ) {
  /* wait for mutex, and atomically set it */
  while( FD_ATOMIC_CAS( mut, 0, 1 ) != 0 ) { }
  FD_TWOSTEP_ASSERT( *mut == 1 );
}

void
mutex_unlock( uint * mut ) {
  *mut = 0;
}


/* shared_data with mutex
 * thread 1 should only move shared_data 0->1->0
 * thread 2 should only move shared_data 0->2->0
 * the mutex should prevent 1->2 or 2->1
 *
 * fd_twostep should detect that the mutex is broken */
uint shared_data = 0;

/* bad mutex implementation */
uint my_mutex[1] = {0};


void
test_init( void ) {
  /* unlock the mutex */
  *my_mutex = 0;

  /* clear the shared data */
  shared_data = 0;
}


void
bad_thread_1( void * v_args ) {
  (void)v_args;

  FD_TWOSTEP_START();

  //volatile int x = 0; (void)x;
  //for( int j = 0; j < 6; ++j ) { x = j; }

  bad_mutex_lock( my_mutex );

  FD_TWOSTEP_ASSERT( shared_data == 0 );

  shared_data = 1;

  FD_TWOSTEP_ASSERT( shared_data == 1 );

  shared_data = 0;

  mutex_unlock( my_mutex );

  FD_TWOSTEP_TERM();
}


void
bad_thread_2( void * v_args ) {
  (void)v_args;

  FD_TWOSTEP_START();

  //volatile int x = 0; (void)x;
  //for( int j = 0; j < 7; ++j ) { x = j; }

  bad_mutex_lock( my_mutex );

  FD_TWOSTEP_ASSERT( shared_data == 0 );

  shared_data = 2;

  FD_TWOSTEP_ASSERT( shared_data == 2 );

  shared_data = 0;

  mutex_unlock( my_mutex );

  FD_TWOSTEP_TERM();
}


void
good_thread_1( void * v_args ) {
  (void)v_args;

  FD_TWOSTEP_START();

  //volatile int x = 0; (void)x;
  //for( int j = 0; j < 6; ++j ) { x = j; }

  good_mutex_lock( my_mutex );

  FD_TWOSTEP_ASSERT( shared_data == 0 );

  shared_data = 1;

  FD_TWOSTEP_ASSERT( shared_data == 1 );

  shared_data = 0;

  mutex_unlock( my_mutex );

  FD_TWOSTEP_TERM();
}


void
good_thread_2( void * v_args ) {
  (void)v_args;

  FD_TWOSTEP_START();

  //volatile int x = 0; (void)x;
  //for( int j = 0; j < 7; ++j ) { x = j; }

  good_mutex_lock( my_mutex );

  FD_TWOSTEP_ASSERT( shared_data == 0 );

  shared_data = 2;

  FD_TWOSTEP_ASSERT( shared_data == 2 );

  shared_data = 0;

  mutex_unlock( my_mutex );

  FD_TWOSTEP_TERM();
}


void
test_bad( void * fibre_1_mem, void * fibre_2_mem, ulong stack_sz ) {
  /* this test is expected to find a race in bad_mutex_lock */
  
  /* interleaving dictated by seed */
  uint seed = 42;

  int fail_cnt = 0;
  int tot_cnt  = 0;

  for( uint j = 0; j < 200; ++j ) {
    test_init();

    /* this could be subsumed by twostep */
    /* this initializes the threads, ready for execution, but doesn't execute them */
    fd_fibre_t * fibre_1 = fd_fibre_start( fibre_1_mem, stack_sz, bad_thread_1, NULL );
    fd_fibre_t * fibre_2 = fd_fibre_start( fibre_2_mem, stack_sz, bad_thread_2, NULL );

    /* run the threads instruction by instruction until end
     * interleaved according to the seed, and verifying any
     * FD_TWOSTEP_ASSERT statements */
    int passed = fd_twostep_run( fibre_1, fibre_2, seed );

    if( !passed ) {
      printf( "Failed with seed: %u\n", seed );
      fflush( stdout );
    }

    seed++;

    fail_cnt += !passed;
    tot_cnt  += 1;

    /* clean up */
    fd_fibre_free( fibre_2 );
    fd_fibre_free( fibre_1 );
  }

  /* output ratio */
  printf( "Test of broken mutex: failed %d/%d\n", fail_cnt, tot_cnt );

  /* this is expected to fail, in which case we output PASSED */
  printf( "%s\n", (fail_cnt) ? "PASSED" : "FAILED" ); fflush( stdout );
}


void
test_good( void * fibre_1_mem, void * fibre_2_mem, ulong stack_sz ) {
  /* this test is expected to find no race in good_mutex_lock */
  
  /* interleaving dictated by seed */
  uint seed = 42;

  int fail_cnt = 0;
  int tot_cnt  = 0;

  for( uint j = 0; j < 200; ++j ) {
    test_init();

    /* this could be subsumed by twostep */
    /* this initializes the threads, ready for execution, but doesn't execute them */
    fd_fibre_t * fibre_1 = fd_fibre_start( fibre_1_mem, stack_sz, good_thread_1, NULL );
    fd_fibre_t * fibre_2 = fd_fibre_start( fibre_2_mem, stack_sz, good_thread_2, NULL );

    /* run the threads instruction by instruction until end
     * interleaved according to the seed, and verifying any
     * FD_TWOSTEP_ASSERT statements */
    int passed = fd_twostep_run( fibre_1, fibre_2, seed );

    if( !passed ) {
      printf( "Failed with seed: %u\n", seed );
      fflush( stdout );
    }

    seed++;

    //printf( "RESULT: %s\n", !passed ? "FAILED" : "PASSED" ); fflush( stdout );
    fail_cnt += !passed;
    tot_cnt  += 1;

    /* clean up */
    fd_fibre_free( fibre_2 );
    fd_fibre_free( fibre_1 );
  }

  /* output ratio */
  printf( "Test of correct mutex: failed %d/%d\n", fail_cnt, tot_cnt );

  /* this is expected to succeed, in which case we output PASSED */
  printf( "%s\n", (!fail_cnt) ? "PASSED" : "FAILED" ); fflush( stdout );
}


int
main( void ) {
  /* initialize fibres */
  void *       main_fibre_mem = aligned_alloc( fd_fibre_init_align(), fd_fibre_init_footprint() );
  fd_fibre_t * main_fibre     = fd_fibre_init( main_fibre_mem );

  /* initialize twostep */
  fd_twostep_init( main_fibre );

  /* create 2 fibres for thread_1 and thread_2 */
  ulong stack_sz = 1<<20;

  void * fibre_1_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  void * fibre_2_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );

  test_bad(  fibre_1_mem, fibre_2_mem, stack_sz );
  test_good( fibre_1_mem, fibre_2_mem, stack_sz );

  free( fibre_1_mem );
  free( fibre_2_mem );

  fd_twostep_fini();

  fd_fibre_free( main_fibre );
  free( main_fibre_mem );

  return 0;
}
