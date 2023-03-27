#ifndef HEADER_fd_src_ballet_runtime_vm_fd_invocation_context_h
#define HEADER_fd_src_ballet_runtime_vm_fd_invocation_context_h

struct fd_vm_invocation_context {
  fd_vm_log_collector_t * log_collector;
  fd_hash_t               blockhash;
}

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_invocation_context_h */
