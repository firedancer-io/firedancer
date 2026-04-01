/* Test for SIMD-0189: SBPF stricter ELF headers */

#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#define PF_X  (1U)
#define PF_R  (4U)

#define MM_RODATA_START   (0x0UL)
#define MM_BYTECODE_START (0x100000000UL)

#define TEST_BIN_MAX (512UL)

static inline fd_elf64_ehdr
get_ehdr( uchar const * bin ) {
  fd_elf64_ehdr h; fd_memcpy( &h, bin, sizeof(h) ); return h;
}
static inline void
set_ehdr( uchar * bin, fd_elf64_ehdr const * h ) {
  fd_memcpy( bin, h, sizeof(*h) );
}
static inline fd_elf64_phdr
get_phdr( uchar const * bin, uint idx ) {
  fd_elf64_phdr h;
  fd_memcpy( &h, bin + sizeof(fd_elf64_ehdr) + idx*sizeof(h), sizeof(h) );
  return h;
}
static inline void
set_phdr( uchar * bin, uint idx, fd_elf64_phdr const * h ) {
  fd_memcpy( bin + sizeof(fd_elf64_ehdr) + idx*sizeof(*h), h, sizeof(*h) );
}

static inline int
peek( void const * bin, ulong bin_sz, fd_sbpf_elf_info_t * info ) {
  fd_sbpf_loader_config_t cfg = { .sbpf_min_version = FD_SBPF_V3,
                                  .sbpf_max_version = FD_SBPF_V3 };
  return fd_sbpf_elf_peek( info, bin, bin_sz, &cfg );
}

static fd_sbpf_program_t *
peek_and_load( uchar * bin, ulong bin_sz ) {
  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_SUCCESS );

  void * rodata = fd_scratch_alloc( FD_SBPF_PROG_RODATA_ALIGN, bin_sz );
  fd_sbpf_program_t * prog = fd_sbpf_program_new(
    fd_scratch_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ),
    &info, rodata );
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new(
    fd_scratch_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );

  fd_sbpf_loader_config_t cfg = { .sbpf_min_version = FD_SBPF_V3,
                                  .sbpf_max_version = FD_SBPF_V3 };
  FD_TEST( fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &cfg, NULL, 0UL )
           == FD_SBPF_ELF_SUCCESS );
  return prog;
}

/* Build a valid SBPF-V3 ELF with 2 program headers:
     PHDR 0  rodata   (PF_R, vaddr 0x0,         8 bytes)
     PHDR 1  bytecode (PF_X, vaddr 0x100000000,  8 bytes) */

static ulong
build_valid_2phdr( uchar buf[ TEST_BIN_MAX ] ) {
  fd_memset( buf, 0, TEST_BIN_MAX );

  ulong phdr_end     = sizeof(fd_elf64_ehdr) + 2*sizeof(fd_elf64_phdr);
  ulong rodata_sz    = 8UL;
  ulong bytecode_sz  = 8UL;

  fd_elf64_ehdr ehdr;
  fd_memset( &ehdr, 0, sizeof(ehdr) );
  ehdr.e_ident[0] = 0x7f;
  ehdr.e_ident[1] = 'E';
  ehdr.e_ident[2] = 'L';
  ehdr.e_ident[3] = 'F';
  ehdr.e_ident[ FD_ELF_EI_CLASS   ] = FD_ELF_CLASS_64;
  ehdr.e_ident[ FD_ELF_EI_DATA    ] = FD_ELF_DATA_LE;
  ehdr.e_ident[ FD_ELF_EI_VERSION ] = 1;
  ehdr.e_machine   = FD_ELF_EM_BPF;
  ehdr.e_version   = 1;
  ehdr.e_entry     = MM_BYTECODE_START;
  ehdr.e_phoff     = sizeof(fd_elf64_ehdr);
  ehdr.e_flags     = FD_SBPF_V3;
  ehdr.e_ehsize    = sizeof(fd_elf64_ehdr);
  ehdr.e_phentsize = sizeof(fd_elf64_phdr);
  ehdr.e_phnum     = 2;
  fd_memcpy( buf, &ehdr, sizeof(ehdr) );

  fd_elf64_phdr ph0 = {0};
  ph0.p_type   = FD_ELF_PT_LOAD;
  ph0.p_flags  = PF_R;
  ph0.p_offset = phdr_end;
  ph0.p_vaddr  = MM_RODATA_START;
  ph0.p_paddr  = MM_RODATA_START;
  ph0.p_filesz = rodata_sz;
  ph0.p_memsz  = rodata_sz;
  set_phdr( buf, 0, &ph0 );

  fd_elf64_phdr ph1 = {0};
  ph1.p_type   = FD_ELF_PT_LOAD;
  ph1.p_flags  = PF_X;
  ph1.p_offset = phdr_end + rodata_sz;
  ph1.p_vaddr  = MM_BYTECODE_START;
  ph1.p_paddr  = MM_BYTECODE_START;
  ph1.p_filesz = bytecode_sz;
  ph1.p_memsz  = bytecode_sz;
  set_phdr( buf, 1, &ph1 );

  return phdr_end + rodata_sz + bytecode_sz;
}

/* Build a valid SBPF-V3 ELF with 1 program header (no rodata):
     PHDR 0  bytecode (PF_X, vaddr 0x100000000,  8 bytes) */

static ulong
build_valid_1phdr( uchar buf[ TEST_BIN_MAX ] ) {
  fd_memset( buf, 0, TEST_BIN_MAX );

  ulong phdr_end    = sizeof(fd_elf64_ehdr) + sizeof(fd_elf64_phdr);
  ulong bytecode_sz = 8UL;

  fd_elf64_ehdr ehdr;
  fd_memset( &ehdr, 0, sizeof(ehdr) );
  ehdr.e_ident[0] = 0x7f;
  ehdr.e_ident[1] = 'E';
  ehdr.e_ident[2] = 'L';
  ehdr.e_ident[3] = 'F';
  ehdr.e_ident[ FD_ELF_EI_CLASS   ] = FD_ELF_CLASS_64;
  ehdr.e_ident[ FD_ELF_EI_DATA    ] = FD_ELF_DATA_LE;
  ehdr.e_ident[ FD_ELF_EI_VERSION ] = 1;
  ehdr.e_machine   = FD_ELF_EM_BPF;
  ehdr.e_version   = 1;
  ehdr.e_entry     = MM_BYTECODE_START;
  ehdr.e_phoff     = sizeof(fd_elf64_ehdr);
  ehdr.e_flags     = FD_SBPF_V3;
  ehdr.e_ehsize    = sizeof(fd_elf64_ehdr);
  ehdr.e_phentsize = sizeof(fd_elf64_phdr);
  ehdr.e_phnum     = 1;
  fd_memcpy( buf, &ehdr, sizeof(ehdr) );

  fd_elf64_phdr ph0 = {0};
  ph0.p_type   = FD_ELF_PT_LOAD;
  ph0.p_flags  = PF_X;
  ph0.p_offset = phdr_end;
  ph0.p_vaddr  = MM_BYTECODE_START;
  ph0.p_paddr  = MM_BYTECODE_START;
  ph0.p_filesz = bytecode_sz;
  ph0.p_memsz  = bytecode_sz;
  set_phdr( buf, 0, &ph0 );

  return phdr_end + bytecode_sz;
}

static void
test_peek_valid_2phdr( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_sbpf_elf_info_t info;

  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_SUCCESS );
  FD_TEST( info.sbpf_version == FD_SBPF_V3 );
  FD_TEST( info.bin_sz   == bin_sz );
  FD_TEST( info.text_off == 8U );
  FD_TEST( info.text_sz  == 8UL  );
  FD_TEST( info.text_cnt == 1U   );
}

static void
test_peek_valid_1phdr( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_1phdr( bin );
  fd_sbpf_elf_info_t info;

  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_SUCCESS );
  FD_TEST( info.sbpf_version == FD_SBPF_V3 );
  FD_TEST( info.bin_sz   == bin_sz );
  FD_TEST( info.text_off == 0U );
  FD_TEST( info.text_sz  == 8UL  );
  FD_TEST( info.text_cnt == 1U   );
}

static void
test_peek_invalid_e_machine( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_machine = FD_ELF_EM_SBPF;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_phnum_zero( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_phnum = 0;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_phdr_table_overflow( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_phnum = 100;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_filesz_ne_memsz( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_phdr ph = get_phdr( bin, 0 );
  ph.p_filesz = 16;
  set_phdr( bin, 0, &ph );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_INVALID_PROGRAM_HEADER );
}

static void
test_peek_offset_not_sequential( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_phdr ph = get_phdr( bin, 1 );
  ph.p_offset += 8UL;
  set_phdr( bin, 1, &ph );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_INVALID_PROGRAM_HEADER );
}

static void
test_peek_entry_unaligned( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_entry = MM_BYTECODE_START + 1UL;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_entry_out_of_range( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_entry = MM_BYTECODE_START + 0x1000UL;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_rodata_phnum_lt_2( void ) {
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );
  fd_elf64_ehdr h = get_ehdr( bin );
  h.e_phnum = 1;
  set_ehdr( bin, &h );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, bin_sz, &info ) == FD_SBPF_ELF_ERR_FAILED_TO_PARSE );
}

static void
test_peek_bin_too_small( void ) {
  uchar bin[ TEST_BIN_MAX ];
  build_valid_2phdr( bin );

  fd_sbpf_elf_info_t info;
  FD_TEST( peek( bin, 56UL, &info ) == FD_SBPF_ELF_ERR_VALUE_OUT_OF_BOUNDS );
}

static void
test_load_2phdr( void ) {
  fd_scratch_push();
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_2phdr( bin );

  fd_sbpf_program_t * prog = peek_and_load( bin, bin_sz );

  FD_TEST( prog->rodata_sz  == 8UL );
  FD_TEST( prog->entry_pc   == 0UL );
  FD_TEST( prog->calldests  == NULL );
  fd_scratch_pop();
}

static void
test_load_1phdr_skip_rodata( void ) {
  fd_scratch_push();
  uchar bin[ TEST_BIN_MAX ];
  ulong bin_sz = build_valid_1phdr( bin );

  fd_sbpf_program_t * prog = peek_and_load( bin, bin_sz );

  FD_TEST( prog->rodata_sz == 0UL );
  FD_TEST( prog->entry_pc  == 0UL );
  FD_TEST( prog->calldests == NULL );
  fd_scratch_pop();
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32MB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  test_peek_valid_2phdr();
  test_peek_valid_1phdr();
  test_peek_invalid_e_machine();
  test_peek_phnum_zero();
  test_peek_phdr_table_overflow();
  test_peek_filesz_ne_memsz();
  test_peek_offset_not_sequential();
  test_peek_entry_unaligned();
  test_peek_entry_out_of_range();
  test_peek_rodata_phnum_lt_2();
  test_peek_bin_too_small();

  test_load_2phdr();
  test_load_1phdr_skip_rodata();

  fd_scratch_detach( NULL );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
