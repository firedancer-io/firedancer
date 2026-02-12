/* fdos_kvm.c provides a KVM hypervisor environment for fdos. */

#include "fdos_kvm.h"
#include "../x86/fd_x86_disasm.h"
#include "../kern/fdos_kern_def.h"
#include <errno.h>
#include <sys/ioctl.h> /* ioctl(2) */

#define TEXT_NORMAL    "\033[0m"
#define TEXT_BOLD      "\033[1m"
#define TEXT_UNDERLINE "\033[4m"
#define TEXT_BLINK     "\033[5m"

#define TEXT_BLUE      "\033[34m"
#define TEXT_GREEN     "\033[32m"
#define TEXT_YELLOW    "\033[93m"
#define TEXT_RED       "\033[31m"

static void *
gvaddr_to_haddr( fdos_env_t const * env,
                 ulong             gvaddr ) {
  void * base = NULL;
  switch( gvaddr>>24 ) {
  case 3:
    base = env->wksp_kern_rodata;
    break;
  case 4:
    base = env->wksp_kern_data;
    break;
  case 5:
    base = env->wksp_kern_stack;
    break;
  }
  if( FD_UNLIKELY( !base ) ) return NULL;
  return fd_wksp_laddr_fast( base, gvaddr&0xffffffUL );
}

static void
hypercall_log( fdos_env_t * kern,
               int          vcpu_fd,
               ulong        level,
               ulong        file_gvaddr,
               ulong        line,
               ulong        func_gvaddr,
               ulong        msg_gvaddr ) {
  static char const * color_level_cstr[] = {
    /* 0 */ TEXT_NORMAL                                  "DEBUG  ",
    /* 1 */ TEXT_BLUE                                    "INFO   " TEXT_NORMAL,
    /* 2 */ TEXT_GREEN                                   "NOTICE " TEXT_NORMAL,
    /* 3 */ TEXT_YELLOW                                  "WARNING" TEXT_NORMAL,
    /* 4 */ TEXT_RED                                     "ERR    " TEXT_NORMAL,
    /* 5 */ TEXT_RED TEXT_BOLD                           "CRIT   " TEXT_NORMAL,
    /* 6 */ TEXT_RED TEXT_BOLD TEXT_UNDERLINE            "ALERT  " TEXT_NORMAL,
    /* 7 */ TEXT_RED TEXT_BOLD TEXT_UNDERLINE TEXT_BLINK "EMERG  " TEXT_NORMAL
  };
  char const * file = (char const *)gvaddr_to_haddr( kern, file_gvaddr );
  char const * func = (char const *)gvaddr_to_haddr( kern, func_gvaddr );
  char const * msg  = (char const *)gvaddr_to_haddr( kern, msg_gvaddr  );


  struct kvm_sregs sregs;
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_GET_SREGS, &sregs )<0 ) ) {
    FD_LOG_ERR(( "KVM_GET_REGS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "%s ring%d  %s(%lu)[%s]: %s",
                  color_level_cstr[ level<sizeof(color_level_cstr)/sizeof(color_level_cstr[0]) ? level : 0 ],
                  sregs.cs.dpl,
                  file, line, func, msg ));
}

void
fdos_hypercall_handler( fdos_env_t *     env,
                        int              vcpu_fd,
                        struct kvm_run * run ) {
  if( FD_UNLIKELY( run->io.size!=4 || run->io.count!=1 ) ) {
    FD_LOG_CRIT(( "invalid io_out hypercall (size=%u,count=%u)", run->io.size, run->io.count ));
  }
  fd_hypercall_args_t const * args = env->hyper_args;
  uint  port = run->io.port;
  ulong arg0 = FD_VOLATILE_CONST( args->arg[0] ); (void)arg0;
  ulong arg1 = FD_VOLATILE_CONST( args->arg[1] ); (void)arg1;
  ulong arg2 = FD_VOLATILE_CONST( args->arg[2] ); (void)arg2;
  ulong arg3 = FD_VOLATILE_CONST( args->arg[3] ); (void)arg3;
  ulong arg4 = FD_VOLATILE_CONST( args->arg[4] ); (void)arg4;
  switch( port ) {
  case FDOS_HYPERCALL_LOG:
    hypercall_log( env, vcpu_fd, arg0, arg1, arg2, arg3, arg4 );
    break;
  default:
    FD_LOG_CRIT(( "invalid hypercall port %u", port ));
  }
  return;
}

static void
trace_rip( fdos_env_t *     env,
           struct kvm_run * run,
           int              vcpu_fd,
           ulong            rip ) {
  (void)env; (void)run;

  struct kvm_regs regs;
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_GET_REGS, &regs )<0 ) ) {
    FD_LOG_ERR(( "KVM_GET_REGS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( !rip ) rip = regs.rip;

  char const * dis = "";
# if FD_HAS_LIBLLVM
  char dis_buf[ FD_X86_DISASM_MAX ];
  dis = fd_x86_disasm( dis_buf, rip, env->text, env->text_sz, FDOS_GPADDR_KERN_CODE+0x1000 );
  if( !dis ) dis = "                                        ";
# endif

  FD_LOG_INFO(( "\033[2mrip=%#lx\033[0m %s \033[2mrsp=%8llx rax=%16llx rbx=%16llx rcx=%16llx rdx=%16llx rsi=%16llx rdi=%16llx\033[0m",
                rip, dis,
                regs.rsp, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi ));
}

int
fdos_kvm_run( fdos_env_t *     kern,
              struct kvm_run * kvm_run,
              int              vcpu_fd ) {
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_RUN, 0 ) )<0 ) {
    if( errno==EINTR ) return 0;
    FD_LOG_ERR(( "KVM_RUN failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  switch( kvm_run->exit_reason ) {
  case KVM_EXIT_IO: /* hypercall */
    if( kvm_run->io.direction==KVM_EXIT_IO_OUT ) {
      fdos_hypercall_handler( kern, vcpu_fd, kvm_run );
    } else {
      FD_LOG_ERR(( "Unexpected INPUT hypercall" ));
    }
    return 0;
  case KVM_EXIT_DEBUG: {
    trace_rip( kern, kvm_run, vcpu_fd, kvm_run->debug.arch.pc );
    return 0;
  }
  case KVM_EXIT_HLT:
    FD_LOG_NOTICE(( "KVM guest issued HLT instruction" ));
    return 1;
  case KVM_EXIT_FAIL_ENTRY:
    FD_LOG_ERR(( "KVM guest failed to enter (hardware_entry_failure_reason=%#llx)", kvm_run->fail_entry.hardware_entry_failure_reason ));
  case KVM_EXIT_SHUTDOWN:
    FD_LOG_WARNING(( "KVM guest shut down (hardware_exit_reason=%#llx)", kvm_run->hw.hardware_exit_reason ));
    return 1;
  case KVM_EXIT_INTERNAL_ERROR:
    FD_LOG_ERR(( "KVM_EXIT_INTERNAL_ERROR (suberror %u)", kvm_run->internal.suberror ));
  default:
    FD_LOG_ERR(( "Unhandled KVM exit reason %u", kvm_run->exit_reason ));
  }
}
