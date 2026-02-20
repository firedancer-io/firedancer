#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../program/fd_bpf_loader_program.h"
#include "../../vm/fd_vm_base.h"
#include "../../progcache/fd_prog_load.h"

#if FD_HAS_FLATCC
#include "flatbuffers/generated/flatbuffers_common_builder.h"
#include "flatbuffers/generated/flatbuffers_common_reader.h"
#include "flatbuffers/generated/elf_reader.h"
#include "flatbuffers/generated/elf_builder.h"
#endif

#define SORT_NAME        sort_ulong
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

#if FD_HAS_FLATCC

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

#endif /* FD_HAS_FLATCC */
