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
  /* 64-bit LE ELF, ET_DYN, EM_SBPF, 4 program headers (bytecode/rodata/stack/heap),
     bytecode at offset 0x120 with 1 instruction: ADD64_IMM dst=r10, imm=0 */
  static char const * hex =
    /* ELF header (64 bytes) */
    "7f454c46020101000000000000000000"
    "0300"
    "0701"
    "01000000"
    "0000000000000000"
    "4000000000000000"
    "0000000000000000"
    "03000000"
    "4000"
    "3800"
    "0400"
    "4000"
    "0100"
    "0000"
    /* Program header 0: PT_LOAD X, vaddr 0x0, offset 0x120, filesz=memsz=8 */
    "01000000" "01000000" "2001000000000000" "0000000000000000" "0000000000000000" "0800000000000000" "0800000000000000" "0800000000000000"
    /* Program header 1: PT_LOAD R, vaddr 0x100000000, offset 0x128, filesz=memsz=0 */
    "01000000" "04000000" "2801000000000000" "0000000001000000" "0000000001000000" "0000000000000000" "0000000000000000" "0800000000000000"
    /* Program header 2: PT_LOAD RW (stack), vaddr 0x200000000, offset 0x128, filesz=0, memsz=0x1000 */
    "01000000" "06000000" "2801000000000000" "0000000002000000" "0000000002000000" "0000000000000000" "0010000000000000" "0800000000000000"
    /* Program header 3: PT_LOAD RW (heap), vaddr 0x300000000, offset 0x128, filesz=0, memsz=0x1000 */
    "01000000" "06000000" "2801000000000000" "0000000003000000" "0000000003000000" "0000000000000000" "0010000000000000" "0800000000000000"
    /* .text at 0x120: ADD64_IMM dst=r10, imm=0 (function start marker), 8 bytes */
    "070a000000000000"
    /* one extra padding byte to keep rodata p_offset (0x128) < file size */
    "00";

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

  FD_TEST( info.text_off==0x120U );
  FD_TEST( info.text_sz ==8UL );
  FD_TEST( info.text_cnt==1U );
  FD_TEST( info.entry_pc==0U );
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
