#include "fd_svm_elfgen.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../util/fd_util.h"

static void
test_elfgen_roundtrip( uchar const * text,
                       ulong         text_sz,
                       uchar const * rodata,
                       ulong         rodata_sz ) {
  fd_scratch_push();

  ulong elf_sz  = fd_svm_elfgen_sz( text_sz, rodata_sz );
  uchar * elf   = fd_scratch_alloc( 8UL, elf_sz );
  fd_svm_elfgen( elf, elf_sz, text, text_sz, rodata, rodata_sz );

  fd_sbpf_elf_info_t info;
  fd_sbpf_loader_config_t config = {
    .elf_deploy_checks = 1,
    .sbpf_min_version  = FD_SBPF_V0,
    .sbpf_max_version  = FD_SBPF_V3,
  };
  int err = fd_sbpf_elf_peek( &info, elf, elf_sz, &config );
  FD_TEST( err==0 );

  void * rodata_buf = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, info.bin_sz );
  FD_TEST( rodata_buf );
  fd_sbpf_program_t * prog = fd_sbpf_program_new(
      fd_scratch_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ),
      &info, rodata_buf );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
      fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  void * scratch = fd_scratch_alloc( 1UL, info.bin_sz );
  err = fd_sbpf_program_load( prog, elf, elf_sz, syscalls, &config, scratch, info.bin_sz );
  FD_TEST( err==0 );

  FD_TEST( prog->info.text_cnt == text_sz/8UL );
  FD_TEST( fd_memeq( prog->text, text, text_sz ) );
  if( rodata_sz ) {
    uchar const * loaded_rodata = (uchar const *)prog->rodata + info.text_off + text_sz;
    FD_TEST( fd_memeq( loaded_rodata, rodata, rodata_sz ) );
  }
  FD_TEST( prog->entry_pc == 0UL );

  fd_scratch_pop();
}

/* A minimal sBPF "exit" instruction: opcode 0x95, imm 0. */
static uchar const exit_insn[8] = { 0x95, 0,0,0, 0,0,0,0 };

static void
test_text_only( void ) {
  test_elfgen_roundtrip( exit_insn, sizeof(exit_insn), NULL, 0UL );
}

static void
test_text_and_rodata( void ) {
  uchar ro[16];
  for( ulong i=0; i<sizeof(ro); i++ ) ro[i] = (uchar)(0xA0+i);
  test_elfgen_roundtrip( exit_insn, sizeof(exit_insn), ro, sizeof(ro) );
}

static void
test_multi_insn_and_rodata( void ) {
  uchar text[16] = {
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* mov64 r0, 0 */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* exit         */
  };
  uchar ro[7] = { 'h','e','l','l','o','\n','\0' };
  test_elfgen_roundtrip( text, sizeof(text), ro, sizeof(ro) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<16 ];
  static ulong scratch_fmem[ 4UL ] __attribute__((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<16, 4UL );

  test_text_only();
  test_text_and_rodata();
  test_multi_insn_and_rodata();

  FD_LOG_NOTICE(( "pass" ));
  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}
