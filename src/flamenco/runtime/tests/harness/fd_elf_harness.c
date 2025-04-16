#include "fd_elf_harness.h"

ulong
fd_runtime_fuzz_sbpf_load_run( fd_runtime_fuzz_runner_t * runner,
                               void const *               input_,
                               void **                    output_,
                               void *                     output_buf,
                               ulong                      output_bufsz ) {
  fd_exec_test_elf_loader_ctx_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_elf_loader_effects_t **  output = fd_type_pun( output_ );

  fd_sbpf_elf_info_t info;
  fd_valloc_t valloc = fd_spad_virtual( runner->spad );

  if ( FD_UNLIKELY( !input->has_elf || !input->elf.data ) ){
    return 0UL;
  }

  ulong elf_sz = input->elf_sz;
  void const * _bin;

  /* elf_sz will be passed as arguments to elf loader functions.
     pb decoder allocates memory for elf.data based on its actual size,
     not elf_sz !.
     If elf_sz is larger than the size of actual elf data, this may result
     in out-of-bounds accesses which will upset ASAN (however intentional).
     So in this case we just copy the data into a memory region of elf_sz bytes

     ! The decoupling of elf_sz and the actual binary size is intentional to test
      underflow/overflow behavior */
  if ( elf_sz > input->elf.data->size ){
    void * tmp = fd_valloc_malloc( valloc, 1UL, elf_sz );
    if ( FD_UNLIKELY( !tmp ) ){
      return 0UL;
    }
    fd_memcpy( tmp, input->elf.data->bytes, input->elf.data->size );
    _bin = tmp;
  } else {
    _bin = input->elf.data->bytes;
  }

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

    if( FD_UNLIKELY( !fd_sbpf_elf_peek( &info, _bin, elf_sz, input->deploy_checks, FD_SBPF_V0, FD_SBPF_V3 ) ) ) {
      /* return incomplete effects on execution failures */
      break;
    }

    void* rodata = fd_valloc_malloc( valloc, FD_SBPF_PROG_RODATA_ALIGN, info.rodata_footprint );
    FD_TEST( rodata );

    fd_sbpf_program_t * prog = fd_sbpf_program_new( fd_valloc_malloc( valloc, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
    FD_TEST( prog );

    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_valloc_malloc( valloc, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));
    FD_TEST( syscalls );

    fd_vm_syscall_register_all( syscalls, 0 );

    int res = fd_sbpf_program_load( prog, _bin, elf_sz, syscalls, input->deploy_checks );
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
    fd_memcpy( &(elf_effects->rodata->bytes), prog->rodata, prog->rodata_sz );

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
