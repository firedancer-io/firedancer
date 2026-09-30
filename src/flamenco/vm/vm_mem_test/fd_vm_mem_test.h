/* This is not test_vm_mem.  This is an extension to fd_vm_mem for
   inclusion in test binaries only that does some strange asm/linker
   tricks to make a version of vm_mem that is much easier to use in
   tests. */
#include "../fd_vm_mem.h"

/* fd_vm_mem_new_test initialize an fd_vm_mem_t AND join the
   caller to it.  m must have the footprint and alignment of an
   fd_vm_mem_t.  This uses static backing memory in a .bss-like segment
   of the executable. Returns m.  Cannot fail.  See the other ways of
   allocating fd_vm_mem_t for more details. */
fd_vm_mem_t * fd_vm_mem_new_test( void * m );
