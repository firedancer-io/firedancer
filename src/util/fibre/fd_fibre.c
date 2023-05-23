#include "fd_fibre.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

fd_fibre_t * fd_fibre_current = NULL;


/* top level function
   simply calls the user function then sets the done flag */
void
fd_fibre_run_fn( void * vp ) {
  fd_fibre_t * fibre = (fd_fibre_t*)vp;

  /* call user function */
  fibre->fn( fibre->arg );

  /* set done flag */
  fibre->done = 1;
}

/* footprint and alignment required for fd_fibre_init */
ulong
fd_fibre_init_footprint( void ) {
  /* size should be a multiple of the alignment */
  return fd_ulong_align_up( sizeof( fd_fibre_t ), FD_FIBRE_ALIGN );
}

ulong
fd_fibre_init_align( void ) {
  return FD_FIBRE_ALIGN;
}


/* initialize main fibre */
fd_fibre_t *
fd_fibre_init( void * mem ) {
  fd_fibre_t * fibre = (fd_fibre_t*)mem;

  memset( fibre, 0, sizeof( *fibre ) );

  fibre->stack    = NULL;
  fibre->stack_sz = 0;

  ucontext_t * ctx = &fibre->ctx;

  if( getcontext( ctx ) == -1 ) {
    fprintf( stderr, "getcontext failed with %d %s\n", errno, strerror( errno ) );
    fflush( stderr );
    fd_fibre_abort();
  }

  fd_fibre_current = fibre;

  return fibre;
}


/* footprint and alignment required for fd_fibre_start */
ulong
fd_fibre_start_footprint( ulong stack_size ) {
  return fd_ulong_align_up( sizeof( fd_fibre_t ), FD_FIBRE_ALIGN  ) +
    fd_ulong_align_up( stack_size, FD_FIBRE_ALIGN );
}

ulong fd_fibre_start_align( void ) {
  return FD_FIBRE_ALIGN;
}


/* start a fibre */

/* this uses get/setcontext to start a new fibre
   the current fibre will continue running, and the new one will be
   inactive, and ready to switch to
   this is cooperative threading
     this fibre may be started on another thread */
fd_fibre_t *
fd_fibre_start( void * mem, ulong stack_sz, fd_fibre_fn_t fn, void * arg ) {
  if( fd_fibre_current == NULL ) {
    fprintf( stderr, "fd_fibre_init must be called before fd_fibre_start\n" );
    fflush( stderr );
    fd_fibre_abort();
  }

  ulong l_mem = (ulong)mem;

  void * stack = (void*)( l_mem + 
      fd_ulong_align_up( sizeof( fd_fibre_t ), FD_FIBRE_ALIGN  ) );

  fd_fibre_t * fibre = (fd_fibre_t*)mem;

  memset( fibre, 0, sizeof( *fibre ) );

  /* set the current value of stack and stack_sz */
  fibre->stack_sz = stack_sz;
  fibre->stack    = stack;

  fibre->fn       = fn;
  fibre->arg      = arg;

  /* start with the current fibre */
  memcpy( &fibre->ctx, &fd_fibre_current->ctx, sizeof( fibre->ctx ) );

  /* set the successor context, for use in the event the fibre terminates */
  fibre->ctx.uc_link = &fd_fibre_current->ctx;

  /* set the stack for the new fibre */
  fibre->ctx.uc_stack.ss_sp   = stack;
  fibre->ctx.uc_stack.ss_size = stack_sz;

  /* make a new context */
  makecontext( &fibre->ctx, (void(*)())fd_fibre_run_fn, 1, fibre );

  return fibre;
}

/* free a fibre

   this frees up the resources of a fibre */
void
fd_fibre_free( fd_fibre_t * fibre ) {
  free( fibre->stack );
  free( fibre );
}

/* switch execution to a fibre

   switches execution to "swap_to"
   "swap_to" must have been created with either fd_fibre_init, or fd_fibre_start */
void
fd_fibre_swap( fd_fibre_t * swap_to ) {
  if( swap_to == fd_fibre_current ) {
    return;
  }

  if( swap_to->done ) return;

  /* set the context to return to as the current context */
  swap_to->ctx.uc_link = &fd_fibre_current->ctx;

  /* store current fibre for popping */
  fd_fibre_t * fibre_pop = fd_fibre_current;

  /* set fd_fibre_current for next execution context */
  fd_fibre_current = swap_to;

  /* switch to new fibre */
  if( swapcontext( &fibre_pop->ctx, &swap_to->ctx ) == -1 ) {
    fprintf( stderr, "swapcontext failed with %d %s\n", errno, strerror( errno ) );
    fflush( stdout );
    fd_fibre_abort();
  }

  /* return value of fibre to its previous value */
  fd_fibre_current = fibre_pop;
}


/* set a clock for scheduler */
long (*fd_fibre_clock)(void);

/* fibre for scheduler */
fd_fibre_t * fd_fibre_scheduler = NULL;

void
fd_fibre_set_clock( long (*clock)(void) ) {
  fd_fibre_clock = clock;
}

/* yield current fibre
   allows another fibre to run */
void
fd_fibre_yield( void ) {
  /* same as yield */
  fd_fibre_wait(0);
}

/* stops running currently executing fibre for a period */
void
fd_fibre_wait( long wait_ns ) {
  /* cannot wait if no scheduler */
  if( fd_fibre_scheduler == NULL ) return;

  /* calc wake time */
  long wake = fd_fibre_clock() + ( wait_ns < 1 ? 1 : wait_ns );

  fd_fibre_current->sched_time = wake;

  fd_fibre_schedule( fd_fibre_current );

  /* switch to the fibre scheduler */
  fd_fibre_swap( fd_fibre_scheduler );
}

/* stops running currently executing fibre until a particular
   time */
void
fd_fibre_wait_until( long resume_time_ns ) {
  long now = fd_fibre_clock();
  if( resume_time_ns <= now ) {
    /* ensure that another fibre gets a chance at some point */
    resume_time_ns = now + 1;
  }

  /* cannot wait if no scheduler */
  if( fd_fibre_scheduler == NULL ) return;

  fd_fibre_current->sched_time = resume_time_ns;

  fd_fibre_schedule( fd_fibre_current );

  /* switch to the fibre scheduler */
  fd_fibre_swap( fd_fibre_scheduler );
}

/* wakes another fibre */
void
fd_fibre_wake( fd_fibre_t * fibre ) {
  if( fd_fibre_current == fibre ) return;

  fibre->sched_time = fd_fibre_clock();
  fd_fibre_schedule( fibre );
}

/* sentinel for run queue */
fd_fibre_t fd_fibre_schedule_queue[1] = {{ .sentinel = 1, .next = fd_fibre_schedule_queue }};

/* add a fibre to the schedule */
void
fd_fibre_schedule( fd_fibre_t * fibre ) {
  if( fd_fibre_clock == NULL ) fd_fibre_abort();

  fd_fibre_t * cur_fibre = fd_fibre_schedule_queue;

  /* remove from schedule */
  while(1) {
    if( cur_fibre->next == fibre ) {
      cur_fibre->next = fibre->next;
    }

    cur_fibre = cur_fibre->next;
    if( cur_fibre->sentinel ) break;
  }

  /* add into schedule at appropriate place for wake time */
  fd_fibre_t * prior = fd_fibre_schedule_queue;
  long wake = fibre->sched_time;

  cur_fibre = prior->next;
  while( !cur_fibre->sentinel && wake > cur_fibre->sched_time ) {
    prior     = cur_fibre;
    cur_fibre = cur_fibre->next;
  }

  /* insert into schedule */
  fibre->next = cur_fibre;
  prior->next = fibre;
}

/* run the current schedule

   returns the time of the next ready fibre
   returns -1 if there are no fibres in the schedule */
long
fd_fibre_schedule_run() {
  /* set the currently running fibre as the scheduler */
  fd_fibre_scheduler = fd_fibre_current;

  while(1) {
    fd_fibre_t * cur_fibre = fd_fibre_schedule_queue->next;
    if( cur_fibre->sentinel ) return -1;

    long      now       = fd_fibre_clock();
    if( cur_fibre->sched_time > now ) {
      /* nothing more to do yet */
      return cur_fibre->sched_time;
    }

    /* remove from schedule */
    fd_fibre_schedule_queue->next = cur_fibre->next;

    /* if fibre done, skip execution */
    if( !cur_fibre->done ) {
      fd_fibre_swap( cur_fibre );
    }
  }

  return -1;
}



