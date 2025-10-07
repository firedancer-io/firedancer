#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#include "generated/elf.pb.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../program/fd_bpf_loader_program.h"
#include "../../vm/fd_vm_base.h"

#define SORT_NAME        sort_ulong
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

ulong
fd_solfuzz_elf_loader_run( fd_solfuzz_runner_t * runner,
                           void const *          input_,
                           void **               output_,
                           void *                output_buf,
                           ulong                 output_bufsz ) {
  fd_exec_test_elf_loader_ctx_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_elf_loader_effects_t **  output = fd_type_pun( output_ );

  fd_sbpf_elf_info_t info;
  fd_spad_t * spad = runner->spad;

  if( FD_UNLIKELY( !input->has_elf ) ) {
    return 0UL;
  }

  /* Occasionally testing elf_sz = 0 and NULL elf_bin */
  ulong  elf_sz  = 0UL;
  void * elf_bin = NULL;
  if( FD_LIKELY( input->elf.data ) ) {
    elf_sz  = input->elf.data->size;
    elf_bin = fd_spad_alloc_check( spad, 8UL, elf_sz );
    fd_memcpy( elf_bin, input->elf.data->bytes, elf_sz );
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
  int err = FD_SBPF_ELF_SUCCESS;
  do{
    fd_features_t feature_set = {0};
    fd_runtime_fuzz_restore_features( &feature_set, &input->features );

    fd_sbpf_loader_config_t config = {
      .elf_deploy_checks = input->deploy_checks,
    };
    fd_bpf_get_sbpf_versions(
        &config.sbpf_min_version,
        &config.sbpf_max_version,
        UINT_MAX,
        &feature_set );

    err = fd_sbpf_elf_peek( &info, elf_bin, elf_sz, &config );
    if( FD_UNLIKELY( err ) ) {
      break;
    }

    void *               rodata   = fd_spad_alloc_check( spad, FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
    fd_sbpf_program_t *  prog     = fd_sbpf_program_new( fd_spad_alloc_check( spad, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
    fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( fd_spad_alloc_check( spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));

    /* Register any syscalls given the active feature set */
    fd_vm_syscall_register_slot(
        syscalls,
        UINT_MAX /* Arbitrary slot, doesn't matter */,
        &feature_set,
        !!config.elf_deploy_checks );

    err = fd_sbpf_program_load( prog, elf_bin, elf_sz, syscalls, &config );
    if( FD_UNLIKELY( err ) ) {
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

    elf_effects->text_cnt = prog->info.text_cnt;
    elf_effects->text_off = prog->info.text_off;
    elf_effects->entry_pc = prog->entry_pc;

    pb_size_t max_calldests_sz = 1U;
    if( FD_LIKELY( prog->calldests ) ) {
      max_calldests_sz += (pb_size_t)fd_sbpf_calldests_cnt( prog->calldests);
    }

    elf_effects->calldests     = FD_SCRATCH_ALLOC_APPEND(l, 8UL, max_calldests_sz * sizeof(uint64_t));
    if( FD_UNLIKELY( _l > output_end ) ) {
      return 0UL;
    }

    /* Add the entrypoint to the calldests */
    elf_effects->calldests[elf_effects->calldests_count++] = prog->entry_pc;

    /* Add the rest of the calldests */
    if( FD_LIKELY( prog->calldests ) ) {
      for( ulong target_pc=fd_sbpf_calldests_const_iter_init(prog->calldests);
                          !fd_sbpf_calldests_const_iter_done(target_pc);
                target_pc=fd_sbpf_calldests_const_iter_next(prog->calldests, target_pc) ) {
        if( FD_LIKELY( target_pc!=prog->entry_pc ) ) {
          elf_effects->calldests[elf_effects->calldests_count++] = target_pc;
        }
      }
    }

    /* Sort the calldests in ascending order */
    sort_ulong_inplace( elf_effects->calldests, elf_effects->calldests_count );
  } while(0);

  elf_effects->error = -err;
  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );

  *output = elf_effects;
  return actual_end - (ulong) output_buf;
}
