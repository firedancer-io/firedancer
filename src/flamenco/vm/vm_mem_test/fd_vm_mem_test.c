#include "fd_vm_mem_test.h"

/* See the dense footprint for details about the sizes of these regions. */
/* The python script rewrites the .p2align to 2 GB (the max lld can
   handle) without bloating the .o or .a file */
#define MAKE_REGION( n, sz )                                        \
__asm__(                                                            \
         ".section .fd_vm_mem_test_region"#n",\"aw\",@nobits\n"     \
         ".p2align 12\n"                                            \
         ".global fd_vm_mem_test_region" #n "\n"                    \
         "fd_vm_mem_test_region" #n ":\n"                           \
         ".space " FD_EXPAND_THEN_STRINGIFY( sz ) "\n"              \
         ".previous\n"                                              \
         ".section .fd_vm_mem_test_region"#n"_pad,\"aw\",@nobits\n" \
         ".p2align 12\n"                                            \
         "fd_vm_mem_test_region" #n "_pad:\n"                       \
         ".space 1\n"                                               \
         ".previous\n"                                              \
    )
/* The assembler doesn't understand sizeof() */
#define _BPF_LOADER_SERIALIZATION_FOOTPRINT 88838192UL
FD_STATIC_ASSERT( _BPF_LOADER_SERIALIZATION_FOOTPRINT==BPF_LOADER_SERIALIZATION_FOOTPRINT, adjust_value );

#define SZ_BEFORE_REGION1 (0x400000000UL/FD_VM_MEM_DIRTY_SCALE + _BPF_LOADER_SERIALIZATION_FOOTPRINT/FD_VM_MEM_DIRTY_SCALE)

MAKE_REGION( 0, 4UL*_BPF_LOADER_SERIALIZATION_FOOTPRINT+SZ_BEFORE_REGION1     );
MAKE_REGION( 1, 4UL*_BPF_LOADER_SERIALIZATION_FOOTPRINT+FD_RUNTIME_ACC_SZ_MAX );
MAKE_REGION( 2, 4UL*_BPF_LOADER_SERIALIZATION_FOOTPRINT+2UL*FD_VM_STACK_MAX   );
MAKE_REGION( 3, 4UL*_BPF_LOADER_SERIALIZATION_FOOTPRINT+FD_VM_HEAP_MAX        );
MAKE_REGION( 4, 5UL*_BPF_LOADER_SERIALIZATION_FOOTPRINT                       );

#undef SZ_BEFORE_REGION1


/* If this variable is accessed in the normal way, it generates a
   large relocation that requires recompiling the program with
   mcmodel=large, but if we are careful, we can get around that. */
extern uchar fd_vm_mem_test_region0[];


fd_vm_mem_t *
fd_vm_mem_new_test( void * shm ) {
  fd_vm_mem_t * m = (fd_vm_mem_t *)shm;
  ulong region0_addr, region1_addr, region2_addr, region3_addr, region4_addr;
  __asm__("movq fd_vm_mem_test_region0@GOTPCREL(%%rip), %0" : "=r"(region0_addr));
  __asm__("movq fd_vm_mem_test_region1@GOTPCREL(%%rip), %0" : "=r"(region1_addr));
  __asm__("movq fd_vm_mem_test_region2@GOTPCREL(%%rip), %0" : "=r"(region2_addr));
  __asm__("movq fd_vm_mem_test_region3@GOTPCREL(%%rip), %0" : "=r"(region3_addr));
  __asm__("movq fd_vm_mem_test_region4@GOTPCREL(%%rip), %0" : "=r"(region4_addr));

  FD_TEST( region0_addr+0x100000000UL==region1_addr );
  FD_TEST( region1_addr+0x100000000UL==region2_addr );
  FD_TEST( region2_addr+0x100000000UL==region3_addr );
  FD_TEST( region3_addr+0x100000000UL==region4_addr );

  fd_vm_mem_new_dense( m, (void *)region0_addr );

  return m;
}
