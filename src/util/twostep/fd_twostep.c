#define _GNU_SOURCE

#include "fd_twostep.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>


#define FLAG_SINGLE_STEP (1u<<8u)

fd_fibre_t * fd_twostep_main = NULL;
int fd_twostep_abort = 0;

static void
set_single_step( void * ucontext ) {
  //printf( "setting single step\n" ); fflush( stdout );
  ucontext_t * uc = (ucontext_t*)ucontext;
  uc->uc_mcontext.gregs[REG_EFL] |= FLAG_SINGLE_STEP;
}

static void
clr_single_step( void * ucontext ) {
  //printf( "clearing single step\n" ); fflush( stdout );
  ucontext_t * uc = (ucontext_t*)ucontext;
  uc->uc_mcontext.gregs[REG_EFL] &= ~FLAG_SINGLE_STEP;
}

static int
get_single_step( void * ucontext ) {
  ucontext_t * uc = (ucontext_t*)ucontext;
  return !!( uc->uc_mcontext.gregs[REG_EFL] & FLAG_SINGLE_STEP );
}

/* ONLY to be called from within the signal handler */
static void
fibre_term( void ) {
  fd_fibre_t * cur = fd_fibre_get_current();

  if( cur == fd_twostep_main ) {
    fprintf( stderr, "Attempting to terminate main thread\n" ); fflush( stderr );
    abort();
  }

  fd_fibre_term( cur );
  fd_fibre_swap( fd_twostep_main );
}


void
handle_trap( int signum, siginfo_t * info, void * ucontext ) {
  (void)signum;
  (void)info;
  (void)ucontext;

  ucontext_t * uc = ucontext;

  /* get the instruction pointer */
  unsigned char * ip = (void*)uc->uc_mcontext.gregs[REG_RIP];

  /* TWOSTEP SYSCALL indicated by "int $3; nop" */
  if( *ip == 0x90 ) {
    /* get syscall from RAX register */
    ulong syscall = (ulong)uc->uc_mcontext.gregs[REG_RAX];

    /* process syscall */
    if( syscall < FD_TWOSTEP_SYSCALL_MAGIC ) return;

    ulong rel_syscall = syscall - FD_TWOSTEP_SYSCALL_MAGIC;

    if( rel_syscall >= FD_TWOSTEP_SYSCALL_LAST  ) return;
    switch( rel_syscall ) {
      case FD_TWOSTEP_SYSCALL_START: set_single_step( ucontext ); break;
      case FD_TWOSTEP_SYSCALL_STOP:  clr_single_step( ucontext ); break;
      case FD_TWOSTEP_SYSCALL_TERM:  fibre_term();                break;
      default: printf( "Unknown twostep_syscall %lx\n", rel_syscall ); fflush( stdout );
    }
    return;
  }

  if( !get_single_step( ucontext ) ) return;

#if 0
  trace_elem_t * elem = &cur_trace->elem[cur_trace->elem_idx];

  if( cur_trace->range_start <= ip && ip < cur_trace->range_end ) {
    cur_trace->elem_idx++;
    if( cur_trace->elem_idx >= cur_trace->elem_cap ) cur_trace->elem_idx = 0;

    elem->ip    = ip;
    elem->flags = uc->uc_mcontext.gregs[REG_EFL];

    int k = 0;
    for( int j = 0; j < NGREG && k < 8; ++j ) {
      // can probably skip changes in IP
      if( j != REG_RIP &&  cur_trace->last_reg[j] != uc->uc_mcontext.gregs[j] ) {
        elem->chgreg[k] = j;
        elem->before[k] = cur_trace->last_reg[j];
        elem->after[k]  = uc->uc_mcontext.gregs[j];
        k++;
      }
    }
    while( k < 8 ) { elem->chgreg[k] = NGREG; k++; }

    memcpy( cur_trace->last_reg, uc->uc_mcontext.gregs,  sizeof( cur_trace->last_reg ) );
  }
#endif

  /* switch back to the run context */
  fd_fibre_swap( fd_twostep_main );

}


/* initialize twostep */
void
fd_twostep_init( fd_fibre_t * main_fibre ) {
  /* track the controlling fibre */
  fd_twostep_main = main_fibre;

  struct sigaction act, oldact;

  memset( &act, 0, sizeof( act ) );

  /* could track segfaults, and handle gracefully */
#if 0
  act.sa_sigaction = handle_segfault;
  act.sa_flags     = SA_SIGINFO;

  if( sigaction( SIGSEGV, &act, &old_sigaction ) ) {
    fprintf( stderr, "Error occurred during sigaction SEGV: %d %s\n", errno, strerror( errno ) );
    exit(1);
  }
#endif

  act.sa_sigaction = handle_trap;
  act.sa_flags     = SA_SIGINFO;

  if( sigaction( SIGTRAP, &act, &oldact ) ) {
    fprintf( stderr, "Error occurred during sigaction TRAP: %d %s\n", errno, strerror( errno ) );
    abort();
  }

}

/* fini twostep */
void
fd_twostep_fini( void ) {
}

/* run the twostep */
/* returns false (0) if any FD_TWOSTEP_ASSERT failed, else 1 */
int
fd_twostep_run( fd_fibre_t * fibre1, fd_fibre_t * fibre2, uint seed ) {
  (void)seed;

  /* abort should be zero at start */
  __asm__ __volatile__( "" : : : "memory" );
  fd_twostep_abort = 0;

  seed = fd_uint_hash( seed );

  while( !fibre1->done && !fibre2->done && !fd_twostep_abort ) {
    __asm__ __volatile__( "" : : : "memory" );

    /* randomize fibre index */
    uint fibre_idx = fd_uint_hash( seed++ ) & 1;

    if( !fibre1->done && fibre_idx == 0 ) {
      //printf( "executing fibre1\n" ); fflush( stdout );
      fd_fibre_swap( fibre1 );
    }

    if( !fibre2->done && fibre_idx == 1 ) {
      //printf( "executing fibre2\n" ); fflush( stdout );
      fd_fibre_swap( fibre2 );
    }
  }

  return !fd_twostep_abort;
}

