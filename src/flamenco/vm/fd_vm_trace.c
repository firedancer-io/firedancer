#include "fd_vm_trace.h"

#include <stdlib.h>

void *
fd_vm_trace_context_new( void * shmem, ulong FD_PARAM_UNUSED max_trace_entries ) {
  return shmem;
}

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
                               ulong register_file[ 11 ] ) {
  fd_vm_trace_entry_t * current_trace_entry = &ctx->trace_entries[ctx->trace_entries_used];

  current_trace_entry->pc = pc;
  current_trace_entry->ic = ic;
  current_trace_entry->cus = cus;
  current_trace_entry->mem_entries_used = 0;
  memcpy( current_trace_entry->register_file, register_file, 11*sizeof(ulong) );

  ctx->trace_entries_used++;                 
}

void
fd_vm_trace_context_add_mem_entry( fd_vm_trace_context_t * ctx,
                                   ulong vm_addr,
                                   ulong sz,
                                   ulong host_addr,
                                   int write ) {
  fd_vm_trace_entry_t * current_trace_entry = &ctx->trace_entries[ctx->trace_entries_used-1];
  fd_vm_trace_mem_entry_t * current_mem_entry = &current_trace_entry->mem_entries[current_trace_entry->mem_entries_used];
  
  uchar * data = (uchar *)host_addr;

  if( write ) {
    current_mem_entry->type = FD_VM_TRACE_MEM_ENTRY_TYPE_WRITE;
  } else {
    current_mem_entry->type = FD_VM_TRACE_MEM_ENTRY_TYPE_READ;
  }

  current_mem_entry->addr = vm_addr;
  current_mem_entry->sz = sz;
  current_mem_entry->data = malloc(sz);
  fd_memcpy( current_mem_entry->data, data, sz );

  current_trace_entry->mem_entries_used++;
}
