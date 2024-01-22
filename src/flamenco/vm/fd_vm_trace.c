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
  current_trace_entry->mem_entries_head = NULL;
  current_trace_entry->mem_entries_tail = NULL;
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
  fd_vm_trace_mem_entry_t * current_mem_entry = fd_valloc_malloc(ctx->valloc, 1, sizeof(fd_vm_trace_mem_entry_t));
  
  current_mem_entry->next = NULL;
  uchar * data = (uchar *)host_addr;

  if( write ) {
    current_mem_entry->type = FD_VM_TRACE_MEM_ENTRY_TYPE_WRITE;
  } else {
    current_mem_entry->type = FD_VM_TRACE_MEM_ENTRY_TYPE_READ;
  }

  current_mem_entry->addr = vm_addr;
  current_mem_entry->sz = sz;
  current_mem_entry->data = fd_valloc_malloc(ctx->valloc, 1, sz);
  fd_memcpy( current_mem_entry->data, data, sz );

  current_trace_entry->mem_entries_used++;
  if (current_trace_entry->mem_entries_head == NULL) {
    current_trace_entry->mem_entries_head = current_mem_entry;
    current_trace_entry->mem_entries_tail = current_mem_entry;
    if (ctx->trace_entries_used > 1) {
      fd_vm_trace_entry_t * prev_trace_entry = NULL;
      for (ulong i = 2; ctx->trace_entries_used >= i; i++) {
        if (ctx->trace_entries[ctx->trace_entries_used-i].mem_entries_tail != NULL) {
          prev_trace_entry = &ctx->trace_entries[ctx->trace_entries_used-i];
          break;
        }
      }
      if (prev_trace_entry != NULL)
        prev_trace_entry->mem_entries_tail->next = current_trace_entry->mem_entries_head;
    }
  } else {
    current_trace_entry->mem_entries_tail->next = current_mem_entry;
    current_trace_entry->mem_entries_tail = current_mem_entry;
  }
}

void
fd_vm_trace_context_destroy( fd_vm_trace_context_t * ctx ) {
  if( ctx == NULL ) {
    return;
  }
  if (ctx->trace_entries_used == 0) {
    return;
  }

  fd_vm_trace_mem_entry_t * iter = ctx->trace_entries[0].mem_entries_head;
  for (ulong i = 1; iter == NULL && i < ctx->trace_entries_used; i++) {
    iter = ctx->trace_entries[i].mem_entries_head;
  }
  while (iter != NULL) {
    fd_vm_trace_mem_entry_t * next = iter->next;
    fd_valloc_free(ctx->valloc, iter);
    iter = next;
  }
}
