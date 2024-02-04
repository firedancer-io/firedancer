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

void
test_pipe_producer( void * vp ) {
  /* arguments */
  fd_fibre_pipe_t * pipe = (fd_fibre_pipe_t*)vp;

  printf( "pipe test producer starting\n" ); fflush( stdout );

  /* transmit at a rate of one message per millisecond
     for one second */
  long run_period   = (long)1e6;
  long run_duration = (long)1e9;
  long send_time    = now + run_period;
  long run_end      = now + run_duration;

  ulong msg = 0;
  while( now < run_end ) {
    /* wait until sent time */
    fd_fibre_wait_until( send_time );

    /* send msg to consumer */
    printf( "writing msg: %lu\n", msg ); fflush( stdout );
    int rtn = fd_fibre_pipe_write( pipe, msg, 0 );
    if( rtn ) {
      printf( "write failed on msg: %lu\n", msg );
      exit(1);
    }

    /* choose another send time */
    send_time += run_period;

    /* increment message */
    msg++;
  }

  printf( "producer finished\n" );
}


void test_pipe_consumer( void * vp ) {
  /* arguments */
  fd_fibre_pipe_t * pipe = (fd_fibre_pipe_t*)vp;

  printf( "pipe test consumer starting\n" ); fflush( stdout );

  long run_period   = (long)1e6;
  long run_duration = (long)1e9;
  long run_end      = now + run_duration;

  /* wait to receive from pipe, and report each message received */
  while( now < run_end ) {
    /* receive message from producer
       wait for up to the period */
    ulong msg = 0;
    int rtn = fd_fibre_pipe_read( pipe, &msg, run_period );

    if( rtn ) {
      printf( "read failed\n" );
      exit(1);
    }

    printf( "msg %lu received at %ld\n", msg, now );
  }

  printf( "consumer finished\n" );
}


void
run_pipe_test( void ) {
  printf( "pipe test starting\n" );

  /* set now to zero for pretty output */
  now = 0;

  /* create a pipe for communicating between fibres */
  ulong  stack_sz     = 1<<20;
  ulong  pipe_entries = 16;
  void * pipe_mem     = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );

  fd_fibre_pipe_t * pipe = fd_fibre_pipe_new( pipe_mem, pipe_entries );

  /* create a fibre each for producer and consumer */
  void * fibre_1_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  void * fibre_2_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );

  fd_fibre_t * fibre_1 = fd_fibre_start( fibre_1_mem, stack_sz, test_pipe_producer, pipe );
  fd_fibre_t * fibre_2 = fd_fibre_start( fibre_2_mem, stack_sz, test_pipe_consumer, pipe );

  /* schedule the fibres */
  fd_fibre_schedule( fibre_1 );
  fd_fibre_schedule( fibre_2 );

  /* run schedule until done */
  while( 1 ) {
    long timeout = fd_fibre_schedule_run();
    if( timeout == -1 ) {
      /* -1 indicates no fibres scheduled */
      break;
    }

    /* advance time to the next scheduled event */
    now = timeout;
  }

  fd_fibre_free( fibre_2 );
  fd_fibre_free( fibre_1 );

  free( fibre_1_mem );
  free( fibre_2_mem );
  free( pipe_mem    );

  printf( "pipe test complete\n" );
}


struct pipe_producer_args {
  fd_fibre_pipe_t * output;
  long              expire;
  long              period;
};
typedef struct pipe_producer_args pipe_producer_args_t;


void
pipe_producer_main( void * vp_args ) {
  /* obtain args */
  pipe_producer_args_t * args = (pipe_producer_args_t*)vp_args;

  /* send periodically - every 1ms (synthetic clock) */
  fd_fibre_pipe_t * output = args->output;
  long              expire = args->expire;
  long              period = args->period;

  /* first send time */
  long send_time = now + period;

  /* producer runs until time limit exceeded */
  long expire_time = now + expire;

  /* msg is just a counter */
  ulong msg = 1;

  /* for return values */
  int rtn;

  while( now < expire_time ) {
    /* wait until next "send" */
    fd_fibre_wait_until( send_time );

    /* set timeout to be the same as period */
    long timeout = period;

    /* log write call */
    printf( "pipe_producer_main: writing %lu\n", msg ); fflush( stdout );

    /* try sending */
    rtn = fd_fibre_pipe_write( output, msg, timeout );

    if( rtn ) {
      printf( "fd_fibre_pipe_write failed\n" );
      exit(1);
    }

    /* update send time for next iteration */
    send_time += period;

    /* increment message */
    msg++;
  }

  printf( "pipe_producer_main: finished\n" );

}


struct pipe_filter_args {
  fd_fibre_pipe_t * input;
  fd_fibre_pipe_t * out1;
  fd_fibre_pipe_t * out2;
  long              period;
};
typedef struct pipe_filter_args pipe_filter_args_t;


void
pipe_filter_main( void * vp_args ) {
  pipe_filter_args_t * args = (pipe_filter_args_t*)vp_args;

  /* receive messages on one pipe, distribute them to two pipes
     alternately */

  fd_fibre_pipe_t * input   = args->input;
  fd_fibre_pipe_t * out1    = args->out1;
  fd_fibre_pipe_t * out2    = args->out2;
  long              period  = args->period;
  long              timeout = period;

  /* loop until read fails */
  while(1) {
    ulong msg = 0;
    int rtn = fd_fibre_pipe_read( input, &msg, timeout );
    if( rtn ) break;

    /* we have a message - choose the out pipe(s) */
    if( msg % 2 == 0 ) {
      rtn = fd_fibre_pipe_write( out1, msg, timeout );
      if( rtn ) {
        printf( "pipe_filter_main: write failed\n" );
        exit(1);
      }
    }

    if( msg % 3 == 0 ) {
      rtn = fd_fibre_pipe_write( out2, msg, timeout );
      if( rtn ) {
        printf( "pipe_filter_main: write failed\n" );
        exit(1);
      }
    }
  }

  printf( "pipe_filter_main complete\n" );
}


struct pipe_consumer_args {
  char const *      name;
  fd_fibre_pipe_t * input;
  long              expire;
};
typedef struct pipe_consumer_args pipe_consumer_args_t;


void
pipe_consumer_main( void * vp_args ) {
  /* obtain args */

  pipe_consumer_args_t *args = (pipe_consumer_args_t*)vp_args;

  fd_fibre_pipe_t * input   = args->input;
  long              expire  = args->expire;

  long expire_time = now + expire;

  /* loop until read fails */
  while( expire_time > now ) {
    ulong msg = 0;
    int rtn = fd_fibre_pipe_read( input, &msg, expire_time - now );
    if( rtn ) break;

    /* we have a message - output it */
    printf( "pipe_consumer_main: %s received msg %lu\n", args->name, msg );
  }

  printf( "pipe_consumer_main: finished\n" );
}


void
run_test_pipe_filter( void ) {
  ulong             pipe_entries = 16;
  ulong             stack_sz     = 1<<20;

  /* create three pipes */
  void *            pipe_1_mem   = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_pipe_t * pipe_1       = fd_fibre_pipe_new( pipe_1_mem, pipe_entries );

  void *            pipe_2_mem   = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_pipe_t * pipe_2       = fd_fibre_pipe_new( pipe_2_mem, pipe_entries );

  void *            pipe_3_mem   = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_pipe_t * pipe_3       = fd_fibre_pipe_new( pipe_3_mem, pipe_entries );

  /* period set to 1 ms */
  long period = (long)1e6;
  long expire = (long)2e7;

  /* start 1 producer, 1 filter and 2 consumer fibres */
  pipe_producer_args_t   producer_args        = { .output = pipe_1, .expire = expire, period };
  pipe_filter_args_t     filter_args          = { .input  = pipe_1, .out1 = pipe_2, .out2 = pipe_3, .period = period };
  pipe_consumer_args_t   consumer_main_1_args = { .name = "main_1", .input = pipe_2, .expire = expire };
  pipe_consumer_args_t   consumer_main_2_args = { .name = "main_2", .input = pipe_3, .expire = expire };

  /* create fibre for pipe_producer_main */
  void *       producer_fibre_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * producer_fibre     = fd_fibre_start( producer_fibre_mem, stack_sz, pipe_producer_main, &producer_args );

  /* create fibre for pipe_filter_main */
  void *       filter_fibre_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * filter_fibre     = fd_fibre_start( filter_fibre_mem, stack_sz, pipe_filter_main, &filter_args );

  /* create fibre for pipe_consumer_1_main */
  void *       consumer_1_fibre_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * consumer_1_fibre     = fd_fibre_start( consumer_1_fibre_mem, stack_sz, pipe_consumer_main, &consumer_main_1_args );

  /* create fibre for pipe_consumer_2_main */
  void *       consumer_2_fibre_mem = aligned_alloc( fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ) );
  fd_fibre_t * consumer_2_fibre     = fd_fibre_start( consumer_2_fibre_mem, stack_sz, pipe_consumer_main, &consumer_main_2_args );

  /* add to schedule */
  fd_fibre_schedule( producer_fibre );
  fd_fibre_schedule( filter_fibre );
  fd_fibre_schedule( consumer_1_fibre );
  fd_fibre_schedule( consumer_2_fibre );


  /* run schedule until done */
  while( 1 ) {
    long timeout = fd_fibre_schedule_run();
    if( timeout == -1 ) {
      /* -1 indicates no fibres scheduled */
      break;
    }

    /* advance time to next event */
    now = timeout;
  }

  /* free fibres */
  fd_fibre_free( producer_fibre );
  fd_fibre_free( filter_fibre );
  fd_fibre_free( consumer_1_fibre );
  fd_fibre_free( consumer_2_fibre );

  /* free fibre mem */
  free( producer_fibre_mem );
  free( filter_fibre_mem );
  free( consumer_1_fibre_mem );
  free( consumer_2_fibre_mem );

  /* free pipe mem */
  free( pipe_1_mem );
  free( pipe_2_mem );
  free( pipe_3_mem );
}


int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  // initialize fibres
  void *       main_fibre_mem = aligned_alloc( fd_fibre_init_align(), fd_fibre_init_footprint() );
  fd_fibre_t * main_fibre     = fd_fibre_init( main_fibre_mem );

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
    if( timeout == -1 ) {
      /* -1 indicates no fibres scheduled */
      break;
    }

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

  run_pipe_test();

  run_test_pipe_filter();

  fd_fibre_free( main_fibre );
  free( main_fibre_mem );

  return 0;
}

