#include "host/fdos_kvm.h"
#include "kern/fdos_kern_def.h"
#include "x86/fd_x86_msr.h"
#include "../util/fd_util.h"

#include <errno.h>
#include <fcntl.h> /* open(2) */
#include <unistd.h> /* close(2) */
#include <sys/ioctl.h> /* ioctl(2) */
#include <sys/mman.h> /* mmap(2) */

FD_IMPORT_BINARY( fdos_kern_img, "build/fdos/kern/x86_64/bin/fdos_kern.elf" );

static void
wksp_map_to_guest_phys( int         vm_fd,
                        uint        slot,
                        fd_wksp_t * wksp,
                        ulong       gpaddr ) {
  fd_shmem_join_info_t info[1];
  FD_TEST( 0==fd_shmem_join_query_by_join( wksp, info ) );

  struct kvm_userspace_memory_region region = {
    .slot            = slot,
    .guest_phys_addr = gpaddr,
    .memory_size     = info->page_sz * info->page_cnt,
    .userspace_addr  = (ulong)wksp
  };
  if( FD_UNLIKELY( ioctl( vm_fd, KVM_SET_USER_MEMORY_REGION, &region )<0 ) ) {
    FD_LOG_ERR(( "KVM_SET_USER_MEMORY_REGION(slot=%u,guest_phys_addr=%#llx,memory_size=%#llx,userspace_addr=%p) failed (%i-%s)",
                 region.slot, region.guest_phys_addr, region.memory_size, (void *)region.userspace_addr, errno, fd_io_strerror( errno ) ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int flag_trace = fd_env_strip_cmdline_contains( &argc, &argv, "--trace" );

  /* Create a VM kernel object */

  int kvm_fd = open( "/dev/kvm", O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( kvm_fd<0 ) ) {
    FD_LOG_ERR(( "open(/dev/kvm) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int kvm_version = ioctl( kvm_fd, KVM_GET_API_VERSION, 0 );
  if( FD_UNLIKELY( kvm_version!=KVM_API_VERSION ) ) {
    FD_LOG_ERR(( "Linux KVM version mismatch (have %i, expected %i)", kvm_version, KVM_API_VERSION ));
  }

  int vm_fd = ioctl( kvm_fd, KVM_CREATE_VM, 0 );
  if( FD_UNLIKELY( vm_fd<0 ) ) {
    FD_LOG_ERR(( "KVM_CREATE_VM failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int vcpu_fd = ioctl( vm_fd, KVM_CREATE_VCPU, 0 );
  if( FD_UNLIKELY( vcpu_fd<0 ) ) {
    FD_LOG_ERR(( "KVM_CREATE_VCPU failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Setup guest kernel data structures */

  fdos_env_t env[1];
  FD_TEST( fdos_env_create( env, fdos_kern_img, fdos_kern_img_sz ) );

  /* Interrupt handler */

  /* Map memory regions into guest physical memory */

  wksp_map_to_guest_phys( vm_fd, 0U, env->wksp_kern_meta,   FDOS_GPADDR_KERN_META   );
  wksp_map_to_guest_phys( vm_fd, 1U, env->wksp_kern_code,   FDOS_GPADDR_KERN_CODE   );
  wksp_map_to_guest_phys( vm_fd, 2U, env->wksp_kern_rodata, FDOS_GPADDR_KERN_RODATA );
  wksp_map_to_guest_phys( vm_fd, 3U, env->wksp_kern_data,   FDOS_GPADDR_KERN_DATA   );
  wksp_map_to_guest_phys( vm_fd, 4U, env->wksp_kern_stack,  FDOS_GPADDR_KERN_STACK  );
  wksp_map_to_guest_phys( vm_fd, 5U, env->wksp_user_stack,  FDOS_GPADDR_USER_STACK  );

  struct kvm_sregs sregs[1];
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_GET_SREGS, sregs )<0 ) ) {
    FD_LOG_ERR(( "KVM_GET_SREGS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  sregs->gdt.base  = env->gdt_gpaddr;
  sregs->gdt.limit = (FDOS_GDT_CNT * sizeof(ulong)) - 1UL;
  memset( sregs->gdt.padding, 0, sizeof(sregs->gdt.padding) );

  sregs->idt.base  = env->idt_gpaddr;
  sregs->idt.limit = (256 * sizeof(fd_x86_idt_gate_t)) - 1UL;

  /* Segment descriptors */

  struct kvm_segment cs = {
    .base     = 0,
    .limit    = 0xffffffff,
    .selector = 0x08, /* ring 0, GDT, entry 1 (code) */
    .present  = 1,
    .type     = 0xb,
    .dpl      = 0,
    .db       = 0,
    .s        = 1,
    .l        = 1,
    .g        = 1
  };
  sregs->cs = cs;
  struct kvm_segment ds = {
    .base     = 0,
    .limit    = 0xffffffff,
    .selector = 0x10, /* ring 0, GDT, entry 2 (data) */
    .type     = 0x3,
    .present  = 1,
    .dpl      = 0,
    .db       = 0,
    .s        = 1,
    .l        = 1,
    .g        = 1
  };
  sregs->ds = ds;
  sregs->es = ds;
  sregs->fs = ds;
  sregs->gs = ds;
  sregs->ss = ds;

  /* Wire up TSS */

  sregs->tr.base     = env->tss_kern_gpaddr;
  sregs->tr.limit    = sizeof(fd_x86_tss64_t)-1UL;
  sregs->tr.selector = 0x28;
  sregs->tr.type     = 0xb;
  sregs->tr.present  = 1;
  sregs->tr.dpl      = 0;
  sregs->tr.s        = 0;
  sregs->tr.g        = 0;

  sregs->ldt.unusable = 1;

  /* Enable long mode */

  sregs->cr3 = (ulong)env->pml4_gpaddr;
  sregs->cr4 =
      FD_X86_CR4_PAE |
      FD_X86_CR4_OSFXSR;

  sregs->cr0 =
      FD_X86_CR0_PE |
      FD_X86_CR0_MP |
      FD_X86_CR0_ET |
      FD_X86_CR0_NE |
      FD_X86_CR0_WP |
      FD_X86_CR0_AM |
      FD_X86_CR0_PG;

  sregs->efer =
      FD_X86_EFER_SCE |
      FD_X86_EFER_LME |
      FD_X86_EFER_LMA;

  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_SET_SREGS, sregs )<0 ) ) {
    FD_LOG_ERR(( "KVM_SET_SREGS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Setup SYSCALL MSRs */

  ulong msr_star = ((ulong)0x08 << 3) | /* kernel CS */
                   ((ulong)0x18 << 3);  /* user CS */

  __attribute__((aligned(alignof(struct kvm_msrs)))) uchar msrs_buf[ sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry) ];
  struct kvm_msrs * msr_req = fd_type_pun( msrs_buf );
  msr_req->nmsrs = 1;
  msr_req->entries[0].index = FD_X86_MSR_STAR;
  msr_req->entries[0].data  = msr_star;
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_SET_MSRS, msr_req )<0 ) ) {
    FD_LOG_ERR(( "KVM_SET_MSRS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Load initial CPU state */

  struct kvm_regs regs = {
    .rdi    = env->entry_args_gvaddr,
    .rip    = env->entry_gvaddr,
    .rflags = 0x2UL | (3<<12),
    .rsp    = env->stack_kern_top_gvaddr,
    .rbp    = env->stack_kern_top_gvaddr
  };
  if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_SET_REGS, &regs )<0 ) ) {
    FD_LOG_ERR(( "KVM_SET_REGS failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Enable guest debugging */

  struct kvm_guest_debug debug = {0};
  if( flag_trace ) {
    debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
    if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_SET_GUEST_DEBUG, &debug )<0 ) ) {
      FD_LOG_ERR(( "KVM_SET_GUEST_DEBUG failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* Map kvm_run struct */

  int mmap_size = ioctl( kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0 );
  if( FD_UNLIKELY( mmap_size<0 ) ) {
    FD_LOG_ERR(( "KVM_GET_VCPU_MMAP_SIZE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct kvm_run * kvm_run = mmap( NULL, (ulong)mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, vcpu_fd, 0 );
  if( FD_UNLIKELY( kvm_run==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(kvm_run) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "Running KVM guest" ));

  /* Run */

  for(;;) {
    if( flag_trace ) {
      struct kvm_guest_debug debug = {0};
      debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
      if( FD_UNLIKELY( ioctl( vcpu_fd, KVM_SET_GUEST_DEBUG, &debug )<0 ) ) {
        FD_LOG_ERR(( "KVM_SET_GUEST_DEBUG failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }
    if( FD_UNLIKELY( 0!=fdos_kvm_run( env, kvm_run, vcpu_fd ) ) ) break;
  }

  /* Clean up */

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( FD_UNLIKELY( munmap( kvm_run, (ulong)mmap_size ) ) ) FD_LOG_ERR(( "munmap(kvm_run) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( vcpu_fd ) ) ) FD_LOG_ERR(( "close(vcpu) failed (%i-%s)",     errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( vm_fd   ) ) ) FD_LOG_ERR(( "close(vm) failed (%i-%s)",       errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( kvm_fd  ) ) ) FD_LOG_ERR(( "close(/dev/kvm) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fdos_env_destroy( env );

  fd_halt();
  return 0;
}
