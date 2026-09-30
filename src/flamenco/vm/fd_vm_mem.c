#define _GNU_SOURCE
#include <sys/mman.h>
#include <linux/mman.h>
#include <errno.h>

#include "fd_vm_mem.h"

fd_vm_mem_t *
fd_vm_mem_new_mmap( void * shm ) {
  fd_vm_mem_t * m = (fd_vm_mem_t *)shm;

  m->dirty = 0UL;

  const int prot       = PROT_READ|PROT_WRITE;
  const int base_flags = MAP_PRIVATE|MAP_ANONYMOUS;

  void * addrs[ FD_VM_MEM_ALLOC_CNT ] = { 0 };
  ulong  addr_cnt = 0UL;

  ulong last_addr = fd_vm_mem_allocs[ FD_VM_MEM_ALLOC_CNT-1UL ].offset + fd_vm_mem_allocs[ FD_VM_MEM_ALLOC_CNT-1UL ].sz;

  int failed = 0;
  for( ulong i=0UL; i<FD_MAX_INSTRUCTION_STACK_DEPTH; i++ ) {
    /* Allocate with PROT_NONE just to ask the kernel for an unused
       region that's big enough. */
    void * base = mmap( NULL, last_addr, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0 );
    if( FD_UNLIKELY( base==MAP_FAILED ) ) {
      FD_LOG_WARNING(( "mmap( NULL, %lx ) failed (%i-%s)", last_addr, errno, fd_io_strerror( errno ) ));
      failed = 1; break;
    }
    FD_LOG_NOTICE(( "base %p", base ));

    addrs[ addr_cnt++ ] = base;
    m->base_addr[ i ]   = (ulong)base;
    for( ulong j=0UL; j<FD_VM_MEM_ALLOC_CNT; j++ ) {
      int    flags = base_flags | MAP_FIXED | fd_int_if( fd_vm_mem_allocs[j].huge, MAP_HUGETLB|MAP_HUGE_2MB, 0 );
      void * addr  = mmap( (void *)((ulong)base+fd_vm_mem_allocs[j].offset), fd_vm_mem_allocs[j].sz, prot, flags, -1, 0UL );
      FD_LOG_NOTICE(( "%lu: %p - %p", j, addr, (void *)((ulong)addr + fd_vm_mem_allocs[j].sz) ));
      if( FD_UNLIKELY( addr==MAP_FAILED ) ) {
        FD_LOG_WARNING(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        failed = 1; break;
      }
      FD_TEST( addr==(void *)((ulong)base+fd_vm_mem_allocs[j].offset) ); /* MAP_FIXED ensures this */
    }
    if( FD_UNLIKELY( failed ) ) break;
  }

  if( FD_UNLIKELY( failed ) ) {
    for( ulong i=0UL; i<addr_cnt; i++ ) {
      if( FD_UNLIKELY( munmap( addrs[ i ], last_addr ) ) ) {
        FD_LOG_WARNING(( "munmap( %p, %lu ) failed (%i-%s)", addrs[i], last_addr, errno, fd_io_strerror( errno ) ));
      }
    }
    return NULL;
  }

  return m;
}


fd_vm_mem_t *
fd_vm_mem_new_dense( void * shm,
                     void * _backing ) {
  fd_vm_mem_t * m = (fd_vm_mem_t *)shm;

  m->dirty = 0UL;
  ulong backing = (ulong)_backing;

  ulong max_sz  = 0UL;
  for( ulong j=0UL; j<FD_VM_MEM_ALLOC_CNT; j++ ) {
    max_sz = fd_ulong_max( max_sz, fd_vm_mem_allocs[j].sz );
  }
  FD_TEST( max_sz*FD_MAX_INSTRUCTION_STACK_DEPTH<0x100000000UL );

  for( ulong i=0UL; i<FD_MAX_INSTRUCTION_STACK_DEPTH; i++ ) {
    m->base_addr[ i ] = backing + max_sz*i;
  }
  for( ulong i=0UL; i<FD_MAX_INSTRUCTION_STACK_DEPTH; i++ ) {
    for( ulong j=0UL; j<FD_VM_MEM_ALLOC_CNT; j++ ) {
      memset( (void *)(m->base_addr[i]+fd_vm_mem_allocs[j].offset), '\0', fd_vm_mem_allocs[j].sz );
    }
  }

  return m;
}

void *
fd_vm_mem_delete_mmap( fd_vm_mem_t * m ) {
  for( ulong i=0UL; i<FD_MAX_INSTRUCTION_STACK_DEPTH; i++ ) {
    for( ulong j=0UL; j<FD_VM_MEM_ALLOC_CNT; j++ ) {
      if( FD_UNLIKELY( munmap( (void *)(m->base_addr[i]+fd_vm_mem_allocs[j].offset), fd_vm_mem_allocs[j].sz ) ) ) {
        FD_LOG_WARNING(( "munmap( %p, %lu ) failed (%i-%s)", (void *)(m->base_addr[i]+fd_vm_mem_allocs[j].offset),
              fd_vm_mem_allocs[j].sz, errno, fd_io_strerror( errno ) ));
      }
    }
  }
  return (void *)m;
}
