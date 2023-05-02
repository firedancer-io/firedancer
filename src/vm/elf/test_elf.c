#include "fd_elf_loader.h"
#include "fd_elf_types.h"
#include "../../util/fd_util.h"
#include <string.h>
#include <stdio.h>
#include <immintrin.h>


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar buf[1024*1024];

  FILE * file = fopen("/home/lheeger/DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8.bin", "r");

  ulong nread = fread(buf, 1, sizeof(buf), file);

  fd_elf64_relocated_sbfp_program_t program;
  fd_elf_relocate_sbpf_program(buf, nread, &program);

  fd_halt();
  return 0;
}

