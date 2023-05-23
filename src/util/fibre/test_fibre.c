#include <stdio.h>
#include <stdlib.h>

#include "fd_fibre.h"


void
fn1( void * vp ) {
  (void)vp;
  printf( "running fn1\n" ); fflush( stdout );
}


void
fn2( void * vp ) {
  (void)vp;
  printf( "running fn2\n" ); fflush( stdout );
}


void
fn3( void * vp ) {
  (void)vp;
  printf( "running fn3\n" ); fflush( stdout );
}


/* tests of fd_fibre_wait and fd_fibre_wait_until */

/* need a synthetic clock */
long now = 0;

long
my_clock(void) {
  return now;
}


// done flag for tests
int done = 0;

void
test1( void * vp ) {
  /* argument to test1 */
  long * arg = (long*)vp;

  /* fetch argument, which is period */
  long period = arg[0];

  while( !done ) {
    printf( "test1 arg(%ld)  now: %ld\n", period, now ); fflush( stdout );

    fd_fibre_wait( period );
  }
}

void
test2( void * vp ) {
  /* arguments */
  long * arg = (long*)vp;

  /* argument is "done" time */
  long done_time = arg[0];

  /* this test simply waits until a particular time
     and then sets a flag */

  printf( "test2: waiting\n" ); fflush( stdout );
  fd_fibre_wait_until( done_time );

  printf( "test2: finished waiting\n" ); fflush( stdout );
  done = 1;
}


int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  // initialize fibres
  void * main_fibre_mem = aligned_alloc( fd_fibre_init_align(), fd_fibre_init_footprint() );
  fd_fibre_t * main_fibre = fd_fibre_init( main_fibre_mem );

  // create 3 fibres for functions fn1, fn2 and fn3
  ulong stack_sz = 1<<20;
  void * fibre_1_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  void * fibre_2_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  void * fibre_3_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );

  fd_fibre_t * fibre_1 = fd_fibre_start( fibre_1_mem, stack_sz, fn1, NULL );
  fd_fibre_t * fibre_2 = fd_fibre_start( fibre_2_mem, stack_sz, fn2, NULL );
  fd_fibre_t * fibre_3 = fd_fibre_start( fibre_3_mem, stack_sz, fn3, NULL );

  // start each fibre, and allow to complete
  fd_fibre_swap( fibre_1 );
  fd_fibre_swap( fibre_2 );
  fd_fibre_swap( fibre_3 );

  fd_fibre_free( fibre_3 );
  fd_fibre_free( fibre_2 );
  fd_fibre_free( fibre_1 );

  free( fibre_1_mem );
  free( fibre_2_mem );
  free( fibre_3_mem );

  // now run test of wait and wait_until

  // needs a clock
  fd_fibre_set_clock( my_clock );

  // prepare some fibres
  long t0_period = (long)1e9;
  void * t0_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * t0 = fd_fibre_start( t0_mem, stack_sz, test1, &t0_period );

  long t1_period = (long)3e9;
  void * t1_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * t1 = fd_fibre_start( t1_mem, stack_sz, test1, &t1_period );

  long t2_period = (long)5e9;
  void * t2_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * t2 = fd_fibre_start( t2_mem, stack_sz, test1, &t2_period );

  long t3_done_time = (long)60e9;
  void * t3_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * t3 = fd_fibre_start( t3_mem, stack_sz, test2, &t3_done_time );

  // add to schedule
  fd_fibre_schedule( t0 );
  fd_fibre_schedule( t1 );
  fd_fibre_schedule( t2 );
  fd_fibre_schedule( t3 );

  // run schedule until done
  while( 1 ) {
    long timeout = fd_fibre_schedule_run();
    if( timeout == -1 ) break;

    now = timeout;
  }

  fd_fibre_free( t0 );
  fd_fibre_free( t1 );
  fd_fibre_free( t2 );
  fd_fibre_free( t3 );

  free( t0_mem );
  free( t1_mem );
  free( t2_mem );
  free( t3_mem );

  fd_fibre_free( main_fibre );
  free( main_fibre_mem );

  return 0;
}

