#ifndef HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h
#define HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h

#include "../util/fd_util_base.h"

#define FD_VM_MEM_PROT_READABLE ( (uchar)0b001 )
#define FD_VM_MEM_PROT_WRITABLE ( (uchar)0b010 )
#define FD_VM_MEM_PROT_COW      ( (uchar)0b100 )

#define FD_VM_MEM_MAP_SUCCESS       (0);
#define FD_VM_MEM_MAP_ERR_ACC_VIO   (1);

struct fd_vm_mem_segment {
  ulong host_addr;
  ulong vm_addr;
  ulong sz;
  uchar prot_flag;
};
typedef struct fd_vm_mem_segment fd_vm_mem_segment_t;

struct fd_vm_mem_map {
  fd_vm_mem_segment_t * segments;
  ulong                 segments_sz;
};
typedef struct fd_vm_mem_map fd_vm_mem_map_t;

ulong fd_vm_mem_map_read_uchar( fd_vm_mem_map_t *   mem_map,
                             ulong            vm_address,
                             uchar *          val );

ulong 
fd_vm_mem_map_read_ushort( fd_vm_mem_map_t *   mem_map,
                              ulong            vm_address,
                              ushort *         val );

ulong 
fd_vm_mem_map_read_uint( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            uint *           val );

ulong 
fd_vm_mem_map_read_ulong( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            ulong *           val );

ulong 
fd_vm_mem_map_write_uchar( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            uchar            val );

ulong 
fd_vm_mem_map_write_ushort( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            ushort        val );

ulong 
fd_vm_mem_map_write_uint( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            uint           val );

ulong 
fd_vm_mem_map_write_ulong( fd_vm_mem_map_t *   mem_map,
                            ulong            vm_address,
                            ulong           val );

FD_PROTOTYPES_BEGIN

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h */
