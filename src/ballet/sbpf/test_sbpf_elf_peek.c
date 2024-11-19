#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#define LOAD_ELF(id) \
  FD_IMPORT_BINARY( id##_elf, "src/ballet/sbpf/fixtures/" #id ".so" );

LOAD_ELF( hello_solana_program )
LOAD_ELF( hello_solana_program_sbpf_v3 )

void test_sbpf_version_default( void ) {
  fd_sbpf_elf_info_t info;

  uint max_version = 1U;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, /* deploy checks */ 1, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==1U, "hello_solana_program v1" );

  fd_sbpf_elf_info_t * res = fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v3_elf, hello_solana_program_sbpf_v3_elf_sz, /* deploy checks */ 1, max_version );
  FD_TEST_CUSTOM( res==NULL, "hello_solana_program v3 unsupported" );
}

void test_sbpf_version_from_elf_header( void ) {
  fd_sbpf_elf_info_t info;

  uint max_version = 3U;

  fd_sbpf_elf_peek( &info, hello_solana_program_elf, hello_solana_program_elf_sz, /* deploy checks */ 1, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==1U, "hello_solana_program v1" );

  fd_sbpf_elf_peek( &info, hello_solana_program_sbpf_v3_elf, hello_solana_program_sbpf_v3_elf_sz, /* deploy checks */ 1, max_version );
  FD_TEST_CUSTOM( info.sbpf_version==3U, "hello_solana_program v3" );
}

int
main(   int argc,
        char ** argv ) {
  fd_boot( &argc, &argv );

  // testing here
  test_sbpf_version_default();
  test_sbpf_version_from_elf_header();

  fd_halt();
  return 0;
}
