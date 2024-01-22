#ifndef HEADER_fd_src_util_fibre_fd_fibre_h
#define HEADER_fd_src_util_fibre_fd_fibre_h

#include <ucontext.h>

#include "../fd_util.h"

#define FD_FIBRE_ALIGN 128UL

/* definition of the function to be called when starting a new fibre */
typedef void (*fd_fibre_fn_t)( void * );

struct fd_fibre {
  ucontext_t    ctx;
  void *        stack;
  size_t        stack_sz;
  fd_fibre_fn_t fn;
  void *        arg;
  int           done;

  /* schedule parameters */
  long              sched_time;
  struct fd_fibre * next;
  int               sentinel;
};
typedef struct fd_fibre fd_fibre_t;


struct fd_fibre_pipe {
  ulong cap;  /* capacity */
  ulong head; /* head index */
  ulong tail; /* tail index */

  fd_fibre_t * writer; /* fibre that's currently waiting for a write, if any */
  fd_fibre_t * reader; /* fibre that's currently waiting for a read, if any */

  ulong * entries;
};
typedef struct fd_fibre_pipe fd_fibre_pipe_t;


/* TODO make thread local */
extern fd_fibre_t * fd_fibre_current;


FD_PROTOTYPES_BEGIN


/* footprint and alignment required for fd_fibre_init */
ulong fd_fibre_init_footprint( void );
ulong fd_fibre_init_align( void );


/* initialize main fibre

   should be called before making any other fibre calls

   creates a new fibre from the current thread, and returns it
   caller should keep the fibre for later freeing

   probably shouldn't run this twice on the same thread

   mem is the memory allocated for this object. Use fd_fibre_init{_align,_footprint} to
     obtain the appropriate size and alignment requirements */

fd_fibre_t *
fd_fibre_init( void * );


/* footprint and alignment required for fd_fibre_start */
ulong fd_fibre_start_footprint( ulong stack_size );
ulong fd_fibre_start_align( void );


/* Start a fibre

   This uses get/setcontext to create a new fibre

   fd_fibre_init must be called once before calling this

   The current fibre will continue running, and the other will be
   inactive, and ready to switch to

   This fibre may be started on this or another thread

   mem is the memory used for the fibre. Use fd_fibre_start{_align,_footprint}
     to determine the size and alignment required for the memory

   stack_sz is the size of the stack required

   fn is the function entry point to call in the new fibre
   arg is the value to pass to function fn */
fd_fibre_t *
fd_fibre_start( void * mem, ulong stack_sz, fd_fibre_fn_t fn, void * arg );


/* Free a fibre

   This frees up the resources of a fibre

   Only call on a fibre that is not currently running */
void
fd_fibre_free( fd_fibre_t * fibre );


/* switch execution to a fibre

   Switches execution to "swap_to"
   The global variable `fd_fibre_current` is updated with the state
   of the currently running fibre before switching */
void
fd_fibre_swap( fd_fibre_t * swap_to );


/* fd_fibre_abort is called when a fatal error occurs */
#ifndef fd_fibre_abort
#  define fd_fibre_abort(...) abort( __VA_ARGS__ )
#endif


/* set a clock for scheduler */
void
fd_fibre_set_clock( long (*clock)(void) );


/* yield current fibre
   allows other fibres to execute */
void
fd_fibre_yield( void );


/* stops running currently executing fibre for a period of time */
void
fd_fibre_wait( long wait_ns );


/* stops running currently executing fibre until a particular
   time */
void
fd_fibre_wait_until( long resume_time_ns );


/* wakes another fibre */
void
fd_fibre_wake( fd_fibre_t * fibre );


/* add a fibre to the schedule */
void
fd_fibre_schedule( fd_fibre_t * fibre );


/* run the current schedule

   returns
     the time of the next ready fibre
     -1 if there are no fibres in the schedule */
long
fd_fibre_schedule_run( void );


/* fibre data structures */

/* pipe

   send data from one fibre to another
   wakes receiving fibre on write */

/* pipe footprint and alignment */

ulong
fd_fibre_pipe_align( void );

ulong
fd_fibre_pipe_footprint( ulong entries );


/* create a new pipe */

fd_fibre_pipe_t *
fd_fibre_pipe_new( void * mem, ulong entries );


/* write a value into the pipe

   can block if there isn't any free space
   timeout allows the blocking to terminate after a period of time

   pipe        the pipe to write to
   value       the value to write
   timeout     the amount of time to wait for the write to complete

   returns     0 successful
               1 there was no space for the write operation */

int
fd_fibre_pipe_write( fd_fibre_pipe_t * pipe, ulong value, long timeout );


/* read a value from the pipe

   read can block if there isn't any data in the pipe

   timeout allows the read to terminate without a result after
     a period of time

   pipe        the pipe to write to
   value       a pointer to the ulong to receive the value
   timeout     number of nanoseconds to wait for a value

   returns     0 successfully read a value from the pipe
               1 timed out without receiving data */
int
fd_fibre_pipe_read( fd_fibre_pipe_t * pipe, ulong *value, long timeout );


FD_PROTOTYPES_END


#endif /* HEADER_fd_src_util_fibre_fd_fibre_h */
