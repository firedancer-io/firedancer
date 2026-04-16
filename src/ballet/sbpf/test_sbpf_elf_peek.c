#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"
#include "../hex/fd_hex.h"

#define LOAD_ELF(id) \
  FD_IMPORT_BINARY( id##_elf, "src/ballet/sbpf/fixtures/" #id ".so" );

LOAD_ELF( hello_solana_program )
LOAD_ELF( hello_solana_program_sbpf_v2 )
LOAD_ELF( hello_solana_program_old_sbpf_v2 )
LOAD_ELF( ptoken_program_v3 )

void test_sbpf_version_default( void ) {
  fd_sbpf_elf_info_t info;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V0;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v2 accepted as v0" );

  int res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( res<0, "hello_solana_program (old) v2 unsupported" );

  res = fd_sbpf_elf_peek( &info, ptoken_program_v3_elf, ptoken_program_v3_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "ptoken_program v3 accepted as v0" );
}

void test_sbpf_version_from_elf_header( void ) {
  fd_sbpf_elf_info_t info;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V2, "hello_solana_program v2" );

  int res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( res<0, "hello_solana_program (old) v2 unsupported" );

  fd_sbpf_elf_peek( &info, ptoken_program_v3_elf, ptoken_program_v3_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V3, "ptoken_program_v3" );
}

void test_sbpf_version_from_elf_header_with_min( void ) {
  fd_sbpf_elf_info_t info;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V2;
  config.sbpf_max_version = FD_SBPF_V3;

  int res = fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, &config );
  FD_TEST_CUSTOM( res<0, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V2, "hello_solana_program v2" );

  res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, &config );
  FD_TEST_CUSTOM( res<0, "hello_solana_program (old) v2 unsupported" );

  fd_sbpf_elf_peek( &info, ptoken_program_v3_elf, ptoken_program_v3_elf_sz, &config );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V3, "ptoken_program_v3" );
}

/* Strict parser hex-based test merged from test_sbpf_elf_peek_strict.c */
static void
test_sbpf_elf_peek_strict_hex( void ) {
  static char const * hex =
    /* ELF header (64 bytes) */
    "7f454c46020101000000000000000000" /* e_ident */
    "0300"                             /* e_type    = ET_DYN (3) */
    "f700"                             /* e_machine = EM_BPF (247) */
    "01000000"                         /* e_version = 1 */
    "0000000001000000"                 /* e_entry   = 0x100000000 */
    "4000000000000000"                 /* e_phoff   = 64 */
    "0000000000000000"                 /* e_shoff   = 0 */
    "03000000"                         /* e_flags   = 3 (SBPF V3) */
    "4000"                             /* e_ehsize  = 64 */
    "3800"                             /* e_phentsize = 56 */
    "0200"                             /* e_phnum   = 2 */
    "0000"                             /* e_shentsize */
    "0000"                             /* e_shnum */
    "0000"                             /* e_shstrndx */
    /* Program header 0: PT_LOAD PF_R (rodata), vaddr 0x0, offset 0xb0, filesz=memsz=8 */
    "01000000" "04000000" "b000000000000000" "0000000000000000" "0000000000000000" "0800000000000000" "0800000000000000" "0800000000000000"
    /* Program header 1: PT_LOAD PF_X (bytecode), vaddr 0x100000000, offset 0xb8, filesz=memsz=8 */
    "01000000" "01000000" "b800000000000000" "0000000001000000" "0000000001000000" "0800000000000000" "0800000000000000" "0800000000000000"
    /* Rodata at 0xb0: 8 zero bytes */
    "0000000000000000"
    /* Bytecode at 0xb8: ADD64_IMM dst=r10, imm=0 (function start marker), 8 bytes */
    "070a000000000000";

  ulong bin_sz = (ulong)strlen( hex ) / 2UL;
  FD_TEST( bin_sz<=512UL );
  uchar bin[ 512 ];
  fd_hex_decode( bin, hex, bin_sz );

  fd_sbpf_loader_config_t config = (fd_sbpf_loader_config_t){ 0 };
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;
  fd_sbpf_elf_info_t info;
  int rc = fd_sbpf_elf_peek( &info, bin, bin_sz, &config );
  FD_TEST( rc==0 );

  FD_TEST( info.text_off==8U );   /* rodata_sz = phdr0.p_memsz = 8 */
  FD_TEST( info.text_sz ==8UL );
  FD_TEST( info.text_cnt==1U );
  FD_TEST( info.bin_sz==bin_sz );
}

int
main(   int argc,
        char ** argv ) {
  fd_boot( &argc, &argv );

  // testing here
  test_sbpf_version_default();
  test_sbpf_version_from_elf_header();
  test_sbpf_version_from_elf_header_with_min();
  test_sbpf_elf_peek_strict_hex();

  fd_halt();
  return 0;
}
