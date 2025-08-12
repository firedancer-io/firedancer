#include "fd_solfuzz.h"
#include "generated/elf.pb.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../vm/fd_vm_base.h"

ulong
fd_solfuzz_elf_loader_run( fd_solfuzz_runner_t * runner,
                           void const *          input_,
                           void **               output_,
                           void *                output_buf,
                           ulong                 output_bufsz ) {
  fd_exec_test_elf_loader_ctx_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_elf_loader_effects_t **  output = fd_type_pun( output_ );

  fd_sbpf_elf_info_t info;

  if( FD_UNLIKELY( !input->has_elf || !input->elf.data ) ) {
    return 0UL;
  }

  void const * elf_bin = input->elf.data->bytes;
  ulong        elf_sz  = input->elf.data->size;

  // Allocate space for captured effects
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_elf_loader_effects_t * elf_effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_elf_loader_effects_t),
                                sizeof (fd_exec_test_elf_loader_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    /* return 0 on fuzz-specific failures */
    return 0UL;
  }
  fd_memset( elf_effects, 0, sizeof(fd_exec_test_elf_loader_effects_t) );

  /* wrap the loader code in do-while(0) block so that we can exit
     immediately if execution fails at any point */

  do{

    if( FD_UNLIKELY( !fd_sbpf_elf_peek( &info, elf_bin, elf_sz, input->deploy_checks, FD_SBPF_V0, FD_SBPF_V3 ) ) ) {
      /* return incomplete effects on execution failures */
      break;
    }

    fd_spad_t * spad = runner->spad;
    void * rodata = fd_spad_alloc_check( spad, FD_SBPF_PROG_RODATA_ALIGN, info.rodata_footprint );

    fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_spad_alloc_check( spad, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_spad_alloc_check( spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));

    fd_vm_syscall_register_all( syscalls, 0 );

    int res = fd_sbpf_program_load( prog, elf_bin, elf_sz, syscalls, input->deploy_checks );
    if( FD_UNLIKELY( res ) ) {
      break;
    }

    fd_memset( elf_effects, 0, sizeof(fd_exec_test_elf_loader_effects_t) );
    elf_effects->rodata_sz = prog->rodata_sz;

    // Load rodata section
    elf_effects->rodata = FD_SCRATCH_ALLOC_APPEND(l, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( prog->rodata_sz ));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }
    elf_effects->rodata->size = (pb_size_t) prog->rodata_sz;
    fd_memcpy( elf_effects->rodata->bytes, prog->rodata, prog->rodata_sz );

    elf_effects->text_cnt = prog->text_cnt;
    elf_effects->text_off = prog->text_off;
    elf_effects->entry_pc = prog->entry_pc;


    pb_size_t calldests_sz = (pb_size_t) fd_sbpf_calldests_cnt( prog->calldests);
    elf_effects->calldests_count = calldests_sz;
    elf_effects->calldests = FD_SCRATCH_ALLOC_APPEND(l, 8UL, calldests_sz * sizeof(uint64_t));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }

    ulong i = 0;
    for(ulong target_pc = fd_sbpf_calldests_const_iter_init(prog->calldests); !fd_sbpf_calldests_const_iter_done(target_pc);
    target_pc = fd_sbpf_calldests_const_iter_next(prog->calldests, target_pc)) {
      elf_effects->calldests[i] = target_pc;
      ++i;
    }
  } while(0);

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );

  *output = elf_effects;
  return actual_end - (ulong) output_buf;
}
