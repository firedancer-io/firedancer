#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#include "generated/elf.pb.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../program/fd_bpf_loader_program.h"
#include "../../vm/fd_vm_base.h"
#include "../../progcache/fd_prog_load.h"

#ifdef FD_HAS_FLATCC
#include "flatbuffers/generated/flatbuffers_common_builder.h"
#include "flatbuffers/generated/flatbuffers_common_reader.h"
#include "flatbuffers/generated/elf_reader.h"
#include "flatbuffers/generated/elf_builder.h"
#endif

#define SORT_NAME        sort_ulong
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

ulong
fd_solfuzz_pb_elf_loader_run( fd_solfuzz_runner_t * runner,
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
    elf_bin = input->elf.data->bytes;
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
    fd_solfuzz_pb_restore_features( &feature_set, &input->features );

    fd_sbpf_loader_config_t config = {
      .elf_deploy_checks = input->deploy_checks,
    };

    fd_prog_versions_t versions = fd_prog_versions( &feature_set, UINT_MAX );
    config.sbpf_min_version = versions.min_sbpf_version;
    config.sbpf_max_version = versions.max_sbpf_version;

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

    void * scratch = fd_spad_alloc( spad, 1UL, elf_sz );
    err = fd_sbpf_program_load( prog, elf_bin, elf_sz, syscalls, &config, scratch, elf_sz );
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

#ifdef FD_HAS_FLATCC
void
fd_solfuzz_fb_elf_loader_build_err_effects( fd_solfuzz_runner_t * runner, int err ) {
  FD_TEST( !SOL_COMPAT_NS(ELFLoaderEffects_start_as_root)( runner->fb_builder ) );
  FD_TEST( !SOL_COMPAT_NS(ELFLoaderEffects_err_code_add)( runner->fb_builder, (uchar)(-err) ) );
  FD_TEST( SOL_COMPAT_NS(ELFLoaderEffects_end_as_root)( runner->fb_builder ) );
}

int
fd_solfuzz_fb_elf_loader_run( fd_solfuzz_runner_t * runner,
                              void const *          input_ ) {
  SOL_COMPAT_NS(ELFLoaderCtx_table_t) input = fd_type_pun_const( input_ );

  fd_spad_t *             spad     = runner->spad;
  flatbuffers_uint8_vec_t elf_bin_ = SOL_COMPAT_NS(ELFLoaderCtx_elf_data( input ));
  uchar const *           elf_bin  = (uchar const*)elf_bin_;
  ulong                   elf_sz   = flatbuffers_uint8_vec_len( elf_bin_ );

  /* Restore feature set */
  fd_features_t feature_set = {0};
  fd_solfuzz_fb_restore_features( &feature_set, SOL_COMPAT_NS(ELFLoaderCtx_features( input )));

  fd_sbpf_loader_config_t config = {
    .elf_deploy_checks = SOL_COMPAT_NS(ELFLoaderCtx_deploy_checks( input )),
  };

  fd_prog_versions_t versions = fd_prog_versions( &feature_set, UINT_MAX );
  config.sbpf_min_version = versions.min_sbpf_version;
  config.sbpf_max_version = versions.max_sbpf_version;

  /* Peek */
  fd_sbpf_elf_info_t info;
  int err = fd_sbpf_elf_peek( &info, elf_bin, elf_sz, &config );
  if( err ) {
    fd_solfuzz_fb_elf_loader_build_err_effects( runner, err );
    return SOL_COMPAT_V2_SUCCESS;
  }

  /* Set up loading context */
  void *               rodata         = fd_spad_alloc_check( spad, FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
  fd_sbpf_program_t *  prog           = fd_sbpf_program_new( fd_spad_alloc_check( spad, fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
  fd_sbpf_syscalls_t * syscalls       = fd_sbpf_syscalls_new( fd_spad_alloc_check( spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ));
  void *               rodata_scratch = fd_spad_alloc_check( spad, 1UL, elf_sz );

  /* Register syscalls given the active feature set. We can pass in an
     arbitrary slot as its just used to check if features should be
     active or not. */
  FD_TEST( !fd_vm_syscall_register_slot( syscalls, UINT_MAX, &feature_set, !!config.elf_deploy_checks ) );

  /* Load */
  err = fd_sbpf_program_load( prog, elf_bin, elf_sz, syscalls, &config, rodata_scratch, elf_sz );
  if( err ) {
    fd_solfuzz_fb_elf_loader_build_err_effects( runner, err );
    return SOL_COMPAT_V2_SUCCESS;
  }

  /**** Capture effects ****/

  /* Error code */
  uchar out_err_code = FD_SBPF_ELF_SUCCESS;

  /* Rodata */
  ulong out_rodata_hash_u64 = fd_hash( 0UL, prog->rodata, prog->rodata_sz );
  SOL_COMPAT_NS(XXHash_t) out_rodata_hash;
  fd_memcpy( out_rodata_hash.hash, &out_rodata_hash_u64, sizeof(ulong) );

  /* Text count */
  ulong out_text_cnt = prog->info.text_cnt;

  /* Text off */
  ulong out_text_off = prog->info.text_off;

  /* Entry PC */
  ulong out_entry_pc = prog->entry_pc;

  /* Calldests */
  ulong   max_out_calldests_cnt = 1UL + ( prog->calldests ? fd_sbpf_calldests_cnt( prog->calldests ) : 0UL );
  ulong * tmp_out_calldests     = fd_spad_alloc_check( spad, alignof(ulong), sizeof(ulong)*max_out_calldests_cnt );
  ulong   out_calldests_cnt     = 0UL;

  /* Add the entrypoint to the calldests */
  tmp_out_calldests[out_calldests_cnt++] = prog->entry_pc;

  /* Add the rest of the calldests */
  if( FD_LIKELY( prog->calldests ) ) {
    for( ulong target_pc=fd_sbpf_calldests_const_iter_init(prog->calldests);
                        !fd_sbpf_calldests_const_iter_done(target_pc);
               target_pc=fd_sbpf_calldests_const_iter_next(prog->calldests, target_pc) ) {
      if( FD_LIKELY( target_pc!=prog->entry_pc ) ) {
        tmp_out_calldests[out_calldests_cnt++] = target_pc;
      }
    }
  }

  /* Sort the calldests in ascending order */
  sort_ulong_inplace( tmp_out_calldests, out_calldests_cnt );

  /* Create output calldests vector */
  ulong out_calldests_hash_u64 = fd_hash( 0UL, tmp_out_calldests, sizeof(ulong) * out_calldests_cnt );
  SOL_COMPAT_NS(XXHash_t) out_calldests_hash;
  fd_memcpy( out_calldests_hash.hash, &out_calldests_hash_u64, sizeof(ulong) );

  /* Build effects */
  SOL_COMPAT_NS(ELFLoaderEffects_create_as_root)( runner->fb_builder, out_err_code, &out_rodata_hash, out_text_cnt, out_text_off, out_entry_pc, &out_calldests_hash );

  return SOL_COMPAT_V2_SUCCESS;
}
#endif
