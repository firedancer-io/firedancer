#ifndef HEADER_fd_src_flamenco_vm_fd_vm_trace_h
#define HEADER_fd_src_flamenco_vm_fd_vm_trace_h

#include "fd_vm_base.h"

#define FD_VM_TRACE_MEM_ENTRY_TYPE_UNKNOWN (0UL)
#define FD_VM_TRACE_MEM_ENTRY_TYPE_READ    (1UL)
#define FD_VM_TRACE_MEM_ENTRY_TYPE_WRITE   (2UL)

struct fd_vm_trace_mem_entry;
typedef struct fd_vm_trace_mem_entry fd_vm_trace_mem_entry_t;

struct fd_vm_trace_mem_entry {
  ulong type;
  ulong addr;
  ulong sz;
  uchar * data;
  fd_vm_trace_mem_entry_t * next;
};

struct fd_vm_trace_entry {
  ulong pc;
  ulong ic;
  ulong cus;
  ulong register_file[11];
  
  ulong                   mem_entries_used;
  fd_vm_trace_mem_entry_t * mem_entries_head;
  fd_vm_trace_mem_entry_t * mem_entries_tail;
};
typedef struct fd_vm_trace_entry fd_vm_trace_entry_t;

struct fd_vm_trace_context {
  ulong                 trace_entries_used;
  ulong                 trace_entries_sz;
  fd_vm_trace_entry_t * trace_entries;

  fd_valloc_t           valloc;
};
typedef struct fd_vm_trace_context fd_vm_trace_context_t;

FD_PROTOTYPES_BEGIN

/* Lifecycle functions */

static FD_FN_UNUSED ulong
fd_vm_trace_context_align( void ) {
  return 8;
}

static FD_FN_UNUSED ulong
fd_vm_trace_context_footprint( ulong max_trace_entries ) {
  return sizeof(max_trace_entries);
}

void *
fd_vm_trace_context_new( void * shmem, ulong max_trace_entries );

fd_vm_trace_context_t *
fd_vm_trace_context_join( void * shctx );

void * 
fd_vm_trace_context_leave( fd_vm_trace_context_t * ctx );

void *
fd_vm_trace_context_delete( void * shctx );


/* Other functions */
void
fd_vm_trace_context_add_entry( fd_vm_trace_context_t * ctx, 
                               ulong pc,
                               ulong ic,
                               ulong cus,
                               ulong register_file[ 11 ] );

void
fd_vm_trace_context_add_mem_entry( fd_vm_trace_context_t * ctx,
                                   ulong vm_addr,
                                   ulong sz,
                                   ulong host_addr,
                                   int write );

void
fd_vm_trace_context_destroy( fd_vm_trace_context_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_trace_h */
