#define _GNU_SOURCE
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/rseq.h>
#include <linux/rseq.h>
#include <unistd.h>
#include <errno.h>

#include "../fd_flamenco_base.h"

sigjmp_buf env;

void
segv_handler( int         sig  FD_FN_UNUSED,
              siginfo_t * info,
              void      * ucontext FD_FN_UNUSED ) {
  __asm__ volatile( "nop\n"
      "xor %%ecx, %%ecx\n"
        "rdpkru\n" /* populates eax */
        "and $0xfffffff3, %%eax\n" /* back to allow all */
        "wrpkru\n"
    : : : "ecx", "edx", "eax" );
  void * addr = info->si_addr;
  (void)addr;
  uint   pkey = info->si_pkey;
  siglongjmp( env, (int)pkey );
}


void
jit_function( int* tile_mem,
              int* jit_mem ) {
  (void)tile_mem;
  /* without FD_VOLATILE, the compiler optimizes this to a vector move
     which reads from .ro_data.  However, we've made .ro_data
     inaccessible to this function, so it segfaults.  In reality, when
     we're producing the jitted function from scratch, we have control
     of that kind of stuff. */
  for( int i=1; i<10; i++ ) FD_VOLATILE( jit_mem[i] ) = i;
  /* This should segfault, e.g. if a bad program tries to fiddle with
     firedancer memory. */
  tile_mem[1]++;
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int pkey;
  int *tile_mem;
  int *jit_mem;

  /* When the kernel tries to deliver the segv, it tries to read the
     glibc restartable sequence pointer in the thread local storage
     block.  pkeys make that section unreadable from within
     jit_function, which makes the kernel trip over itself when
     delivering the signal, and the segv_handler doesn't actually get
     called.  We can unregister it manually. */

  /* __rseq_offset is documented as Offset from the thread pointer to
     the rseq area. */
  struct rseq *r = (struct rseq *)((char *)__builtin_thread_pointer() + __rseq_offset);
  if( FD_UNLIKELY( syscall( SYS_rseq, r, 32, RSEQ_FLAG_UNREGISTER, RSEQ_SIG ) ) ) FD_LOG_ERR(( "syscall(SYS_rseq) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ulong page_sz = (ulong)getpagesize();

  tile_mem = mmap( NULL, page_sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0 );
  if( FD_UNLIKELY( tile_mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap( 1 page, R|W ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  *tile_mem = (int)getpid();
  FD_LOG_NOTICE(( "buffer %p contains: %d", (void *)tile_mem, *tile_mem ));

  pkey = pkey_alloc( 0, 0 );
  if( FD_UNLIKELY( pkey==-1 ) ) FD_LOG_ERR(( "pkey_alloc( 0, 0 ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  /* We actually require it to return pkey 1 since we don't really have
     a way to pass the value around */
  if( FD_UNLIKELY( pkey!=1 ) ) FD_LOG_ERR(( "pkey_alloc( 0, 0 ) must return 1" ));

  struct sigaction segv_action[1] = {{
    .sa_sigaction = segv_handler,
    .sa_mask      = {{0}},
    .sa_flags     = (int)(SA_SIGINFO | SA_RESETHAND)
  }};
  struct sigaction old_action [1];
  if( FD_UNLIKELY( sigaction( SIGSEGV, segv_action, old_action ) ) ) FD_LOG_ERR(( "sigaction( SIGSEGV ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  int file = open( "/proc/self/maps", O_RDONLY );
  if( FD_UNLIKELY( file==-1 ) ) FD_LOG_ERR(( "open( \"/proc/self/maps\", O_RDONLY ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ulong line_off = 0UL;
  char filebuf[1<<12];
  while( 1 ) {
    ssize_t rval = read( file, filebuf+line_off, sizeof(filebuf)-1UL-line_off );
    if( rval==0 ) break;
    if( rval<0  ) FD_LOG_ERR(( "read( file, filebuf+%lu, %lu ) failed (%d-%s)", line_off, sizeof(filebuf)-1UL-line_off, errno, fd_io_strerror( errno ) ));
    filebuf[ rval ] = '\0';

    ulong line_start = 0UL;
    while( filebuf[line_start] ) {
      ulong line_end = line_start;
      for(; filebuf[line_end] && filebuf[line_end]!='\n'; line_end++ ) ;
      if( !filebuf[line_end] ) break;
      filebuf[line_end] = '\n';
      ulong start_addr, end_addr;
      char sprot[4] = {0};
      if( 3!=sscanf( filebuf+line_start, "%lx-%lx %4s", &start_addr, &end_addr, sprot ) ) break;

      int prot = (sprot[0]=='r' ? PROT_READ  : PROT_NONE) |
                 (sprot[1]=='w' ? PROT_WRITE : PROT_NONE) |
                 (sprot[2]=='x' ? PROT_EXEC  : PROT_NONE);

      if( start_addr >= 0x8000000000000000UL ) {
        FD_LOG_NOTICE(( "Skipping %lx to %lx %4s", start_addr, end_addr, sprot ));
      } else {
        FD_LOG_NOTICE(( "Protecting %lx to %lx %4s", start_addr, end_addr, sprot ));

        if( FD_UNLIKELY( -1==pkey_mprotect( (void *)start_addr, end_addr-start_addr, prot, pkey ) ))
          FD_LOG_ERR(( "pkey_mprotect( %p, %lu, %s, %i ) failed (%d-%s)", (void *)start_addr, end_addr-start_addr, sprot, (int)pkey, errno, fd_io_strerror( errno ) ));
      }

      line_start = line_end+1UL;
    }
    memmove( filebuf, filebuf+line_start, (ulong)rval-line_start );
    line_off = (ulong)rval-line_start;
  }


  /* This memory is not protected, so it IS accessible to the jitted
     program. */
  jit_mem = mmap( (void *)0x100000000UL, page_sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0 );
  if( FD_UNLIKELY( jit_mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap( 1 page, R|W ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  uchar * jit_stack = mmap( NULL, 64UL*page_sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0 );
  if( FD_UNLIKELY( jit_stack==MAP_FAILED ) ) FD_LOG_ERR(( "mmap( 64 pages, R|W ) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "JIT stack %p to %p", jit_stack, jit_stack + 64UL*page_sz ));

  /* Memory is accessible here */
  tile_mem[1] += 4;
  jit_mem [1] += 4;

  int success = 0;
  if( !sigsetjmp( env, 1 ) ) {
    __asm__ volatile(
        "pushq %%r8\n"
        "pushq %%r9\n"
        "pushq %%r10\n"
        "pushq %%r11\n"
        "movq  %%rsp, %%r12\n"
        "rdpkru\n" /* populates eax */
        "and $0xfffffff3, %%eax\n"
        "or $4, %%eax\n" /* disable access */
        "wrpkru\n"
        "movq $0, -8(%[jit_stack])\n" /* test we can still access the jit_stack */
        "movq  %[jit_stack], %%rsp\n"
        "call jit_function\n"
        /* Okay to clobber return val in eax? */
        "xor %%ecx, %%ecx\n"
        "rdpkru\n" /* populates eax */
        "and $0xfffffff3, %%eax\n" /* back to allow all */
        "wrpkru\n"
        "movq  %%r12, %%rsp\n"
        "popq %%r11\n"
        "popq %%r10\n"
        "popq %%r9\n"
        "popq %%r8\n"
        : : "a"(0), "c"(0), "d"(0), [jit_mem]"S"(jit_mem), [tile_mem]"D"(tile_mem), [jit_stack]"r"(jit_stack + 63UL*page_sz)
        : "cc", "memory", "r12" );

    success = 1;
    /* Now it's okay to access tile_mem and jit_mem */
    tile_mem[2] += 3;
    tile_mem[3] += jit_mem[1];
  }

  if( FD_UNLIKELY( !success ) ) {
    /* jit_function segfaulted. The handler already re-enabled access to
       pkey-protected memory.  At this point, we've recovered
       successfully though */
    FD_LOG_WARNING(( "handled jit_function segfault" ));
  } else {
    FD_LOG_NOTICE(( "success" ));
  }


  /* The documentation is a little unclear here, but I think pkey is not
     "still in use," so it's okay to free. */
  if( FD_UNLIKELY( pkey_free( pkey ) ) ) FD_LOG_ERR(( "pkey_free( %i ) failed (%d-%s)", (int)pkey, errno, fd_io_strerror( errno ) ));

  fd_halt();
  return 0;
}
