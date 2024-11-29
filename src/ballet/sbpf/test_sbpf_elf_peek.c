#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#define LOAD_ELF(id) \
  FD_IMPORT_BINARY( id##_elf, "src/ballet/sbpf/fixtures/" #id ".so" );

LOAD_ELF( hello_solana_program )
LOAD_ELF( hello_solana_program_sbpf_v2 )
LOAD_ELF( hello_solana_program_old_sbpf_v2 )

void test_sbpf_version_default( void ) {
  fd_sbpf_elf_info_t info;

  uint min_version = FD_SBPF_V0;
  uint max_version = FD_SBPF_V0;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v2 accepted as v0" );

  fd_sbpf_elf_info_t * res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( res==NULL, "hello_solana_program (old) v2 unsupported" );
}

void test_sbpf_version_from_elf_header( void ) {
  fd_sbpf_elf_info_t info;

  uint min_version = FD_SBPF_V0;
  uint max_version = FD_SBPF_V2;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V0, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V2, "hello_solana_program v2" );

  fd_sbpf_elf_info_t * res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( res==NULL, "hello_solana_program (old) v2 unsupported" );
}

void test_sbpf_version_from_elf_header_with_min( void ) {
  fd_sbpf_elf_info_t info;

  uint min_version = FD_SBPF_V2;
  uint max_version = FD_SBPF_V2;

  fd_sbpf_elf_info_t * res = fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( res==NULL, "hello_solana_program v0" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v2_elf, hello_solana_program_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==FD_SBPF_V2, "hello_solana_program v2" );

  res = fd_sbpf_elf_peek( &info, hello_solana_program_old_sbpf_v2_elf, hello_solana_program_old_sbpf_v2_elf_sz, /* deploy checks */ 1, min_version, max_version );
  FD_TEST_CUSTOM( res==NULL, "hello_solana_program (old) v2 unsupported" );
}

int
main(   int argc,
        char ** argv ) {
  fd_boot( &argc, &argv );

  // testing here
  test_sbpf_version_default();
  test_sbpf_version_from_elf_header();
  test_sbpf_version_from_elf_header_with_min();

  fd_halt();
  return 0;
}
