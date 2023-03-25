#ifndef HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h
#define HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h

#define FD_VM_MEM_PROT_READABLE ( (uchar)0b001 )
#define FD_VM_MEM_PROT_WRITABLE ( (uchar)0b010 )
#define FD_VM_MEM_PROT_COW      ( (uchar)0b100 )

struct fd_vm_mem_segment {
  ulong host_addr;
  ulong vm_addr;
  ulong sz;
  uchar prot_flag;
}
typedef struct fd_vm_mem_segment fd_vm_mem_segment_t;

struct fd_vm_mem_map {
  fd_vm_mem_segment_t * segments;
  ulong                 segments_sz;
}
typedef struct fd_vm_mem_map fd_vm_mem_map_t;

FD_PROTOTYPES_BEGIN

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_mem_map_h */
