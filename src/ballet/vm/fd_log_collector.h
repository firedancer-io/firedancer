#ifndef HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h
#define HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h

#include "../../fd_ballet_base.h"

#define FD_VM_LOG_COLLECTOR_BYTES_LIMIT (10000UL)

struct fd_vm_log_collector {
  uchar buf[ FD_VM_LOG_COLLECTOR_BYTES_LIMIT ];
  ulong buf_used;
};
typedef struct fd_vm_log_collector fd_vm_log_collector_t;

fd_vm_log_collector_t * 
fd_vm_log_collector_init( fd_vm_log_collector_t * log_collector );

void
fd_vm_log_collector_log( fd_vm_log_collector_t *  log_collector, 
                         uchar *                  msg, 
                         ulong                    msg_len );

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h */
