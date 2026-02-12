/* Entrypoint for FiredancerOS kernel */

#include "fdos_hypercall.h"
#include "../../util/log/fd_log.h"
#include <stdarg.h>
#include <stdio.h>

/* fd_util system environment *****************************************/

static fd_hypercall_args_t volatile * g_hyper = NULL;

long
fd_log_wallclock( void ) {
  return (long)fd_tickcount();
}

#define FD_LOG_BUF_SZ (32UL*4096UL)

static char fd_log_private_log_msg[ FD_LOG_BUF_SZ ];
static ulong
hypercall_log( ulong arg0,
               ulong arg1,
               ulong arg2,
               ulong arg3,
               ulong arg4 ) {
  g_hyper->arg[0] = arg0;
  g_hyper->arg[1] = arg1;
  g_hyper->arg[2] = arg2;
  g_hyper->arg[3] = arg3;
  g_hyper->arg[4] = arg4;

  __asm__ volatile (
    "movw %[port], %%dx;\n"
    "outsl;\n"
    :
    : [port] "r" ((ushort)FDOS_HYPERCALL_LOG)
    : "rdx", "memory"
  );

  return g_hyper->arg[0];
}

char const *
fd_log_private_0( char const * fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( fd_log_private_log_msg, FD_LOG_BUF_SZ, fmt, ap );
  if( len<0                        ) len = 0;                        /* cmov */
  if( len>(int)(FD_LOG_BUF_SZ-1UL) ) len = (int)(FD_LOG_BUF_SZ-1UL); /* cmov */
  fd_log_private_log_msg[ len ] = '\0';
  va_end( ap );
  return fd_log_private_log_msg;
}

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {
  (void)now;
  hypercall_log(
      /* arg0 */ (ulong)level,
      /* arg1 */ (ulong)file,
      /* arg2 */ (ulong)line,
      /* arg3 */ (ulong)func,
      /* arg4 */ (ulong)msg
  );
}

__attribute__((noreturn)) void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {
  (void)now;
  hypercall_log(
      /* arg0 */ (ulong)level,
      /* arg1 */ (ulong)file,
      /* arg2 */ (ulong)line,
      /* arg3 */ (ulong)func,
      /* arg4 */ (ulong)msg
  );
  __asm__ volatile ("hlt");
  for(;;) {}
}

/* Context switching **************************************************/

void
syscall_handler( void );

struct fd_jmp_buf {
  ulong rbx;
  ulong rbp;
  ulong r12;
  ulong r13;
  ulong r14;
  ulong r15;
  ulong rsp;
  ulong ret;
};

typedef struct fd_jmp_buf fd_jmp_buf_t;

fd_jmp_buf_t g_sysret;

static void
hello_ring3( void ) {
  FD_LOG_NOTICE(( "Hello from ring 3!" ));
  FD_LOG_NOTICE(( "Returning to ring 0" ));
  __asm__ volatile (
      "movq $1, %rax;\n"
      "syscall;\n"
  );
}

static void
bounce_ring3( void ) {
  __asm__ volatile (
      "syscall;\n"
  );
}

__attribute__((naked)) void
enter_ring3( ulong user_stack_top_gpaddr,
             ulong function ) {
  __asm__ volatile (
      "pushq $0x23;\n" /* segment 4 */
      "pushq %rdi;\n"  /* user stack */
      "pushq $0x1b;\n" /* segment 3 */
      "pushq %rsi;\n"
      "movl $0x23, %eax;\n"
      "movw %ax, %ds;\n"
      "movw %ax, %es;\n"
      "movw %ax, %fs;\n"
      "movw %ax, %gs;\n"
      "lretq;\n"
  );
}

__attribute__((naked)) uint
setjmp( void ) {
  __asm__ volatile (
      "movabsq $g_sysret, %rsi;\n"
      "movq %rbx, (%rsi);\n"
      "movq %rbp, 8(%rsi);\n"
      "movq %r12, 16(%rsi);\n"
      "movq %r13, 24(%rsi);\n"
      "movq %r14, 32(%rsi);\n"
      "movq %r15, 40(%rsi);\n"
      "leaq 8(%rsp), %rdx;\n"
      "movq %rdx, 48(%rsi);\n"
      "movq (%rsp), %rdx;\n"
      "movq %rdx, 56(%rsi);\n"
      "xorl %eax, %eax;\n"
      "retq;\n"
  );
}

__attribute__((naked)) void
longjmp( void ) {
  __asm__ volatile (
      "movabsq $g_sysret, %rdi;\n"
      "movq (%rdi), %rbx;\n"
      "movq 8(%rdi), %rbp;\n"
      "movq 16(%rdi), %r12;\n"
      "movq 24(%rdi), %r13;\n"
      "movq 32(%rdi), %r14;\n"
      "movq 40(%rdi), %r15;\n"
      "movq 48(%rdi), %rsp;\n"
      "jmp *56(%rdi);\n"
  );
}

static void
setup_lstar( void ) {
  __asm__ volatile (
      "movl $0xc0000082, %%ecx;\n"
      "movq $longjmp, %%rax;\n"
      "movq %%rax, %%rdx;\n"
      "shrq $32, %%rdx;\n"
      "wrmsr;\n"
      :
      : : "rax", "rcx", "rdx", "memory"
  );
}

__attribute__((noreturn)) void
fdos_kern_main( fdos_kern_args_t * args ) {
  g_hyper = (fd_hypercall_args_t *)args->hyper_args_gvaddr;

  FD_LOG_NOTICE(( "Hello world!" ));

  setup_lstar();

  FD_LOG_NOTICE(( "Entering ring 3 user stack top %#lx", args->stack_user_top_gvaddr ));
  ulong const user_stack_top_gpaddr = args->stack_user_top_gvaddr;
  if( setjmp()==0 ) {
    enter_ring3( user_stack_top_gpaddr, (ulong)hello_ring3 );
  } else {
    FD_LOG_NOTICE(( "Returned from ring 3" ));
  }
  FD_LOG_NOTICE(( "Doing 10 million context switches" ));

  for( ulong i=0UL; i<10000000UL; i++ ) {
    if( setjmp()==0 ) {
      enter_ring3( user_stack_top_gpaddr, (ulong)bounce_ring3 );
    }
  }

  FD_LOG_ERR(( "Goodbye" ));
  __asm__ volatile ("hlt");
  for(;;) {}
}

__attribute__((noreturn)) void
fdos_kern_entry( fdos_kern_args_t * args ) {

  /* On entry, our GDT, code, and data segment selectors were set up by
     the host.  However, we will need to far return to make the content
     of these structures take changes.  Otherwise, we would run in some
     undocumented KVM guest default state. */

  __asm__ volatile (
      /* Select segment 1, privilege level 0 */
      "pushq $8;\n"
      /* Return address (entry1) */
      "movabsq $fdos_kern_main, %%rax;\n"
      "pushq %%rax;\n"
      /* First argument to entry1 */
      "movq %0, %%rdi;\n"
      /* Far return */
      "lretq;\n"
      : : "r" (args) : "rax", "rdi", "memory"
  );

  __builtin_unreachable();
}
