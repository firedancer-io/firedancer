#ifndef HEADER_fd_src_util_twostep_fd_twostep_h
#define HEADER_fd_src_util_twostep_fd_twostep_h

#include <ucontext.h>
#include <stdio.h>

#include "../fd_util.h"
#include "../fibre/fd_fibre.h"

#define FD_TWOSTEP_ALIGN 128UL

/* used by FD_TWOSTEP_ASSERT to terminate fd_twostep_run */
extern int fd_twostep_abort;

FD_PROTOTYPES_BEGIN

/* syscall is for communicating with TWOSTEP, but in the
 * TWOSTEP context
 * SYSCALL with zero arguments
 * moves the SYSCALL into the rax register, then emits "int $3; nop"
 * which the signal handler looks for, along with the SYSCALL_MAGIC */
#define FD_TWOSTEP_SYSCALL_0( SYSCALL ) \
  __asm__ __volatile__( "\n"            \
                        "\t" "mov %0, %%rax"    "\n"  \
                        "\t" "int $3"          "\n"  \
                        "\t" "nop"             "\n"  \
      : : "i" (FD_TWOSTEP_SYSCALL_MAGIC + (SYSCALL)) : "memory", "rax" )

#define FD_TWOSTEP_START() FD_TWOSTEP_SYSCALL_0( FD_TWOSTEP_SYSCALL_START )
#define FD_TWOSTEP_STOP()  FD_TWOSTEP_SYSCALL_0( FD_TWOSTEP_SYSCALL_STOP  )
#define FD_TWOSTEP_TERM()  FD_TWOSTEP_SYSCALL_0( FD_TWOSTEP_SYSCALL_TERM  )

/* MAGIC is used to distinguish a TWOSTEP SYSCALL from a random number */
#define FD_TWOSTEP_SYSCALL_MAGIC 0x25139251U
#define FD_TWOSTEP_SYSCALL_START 0x00
#define FD_TWOSTEP_SYSCALL_STOP  0x01
#define FD_TWOSTEP_SYSCALL_TERM  0x02

/* last entry */
#define FD_TWOSTEP_SYSCALL_LAST  0xFF

/* assert designed to terminate the current fd_towstep_run on failure */
#define FD_TWOSTEP_ASSERT(...)        \
  do {                                \
    FD_TWOSTEP_STOP();                \
    int failed = !( __VA_ARGS__ );    \
    if( failed ) {                    \
      printf( "Failed ASSERT at %s:%u [%s]\n", __FILE__, (uint)(__LINE__), #__VA_ARGS__ ); \
      fflush( stdout );               \
      fd_twostep_abort = 1;           \
    }                                 \
    FD_TWOSTEP_START();               \
  } while(0)


/* initialize twostep */
void
fd_twostep_init( fd_fibre_t * main_fibre );

/* fini twostep */
void
fd_twostep_fini( void );

/* run the twostep */
/* returns false (0) if any FD_TWOSTEP_ASSERT failed, else 1 */
int
fd_twostep_run( fd_fibre_t * fibre1, fd_fibre_t * fibre2, uint seed );



FD_PROTOTYPES_END


#endif /* HEADER_fd_src_util_twostep_fd_twostep_h */
