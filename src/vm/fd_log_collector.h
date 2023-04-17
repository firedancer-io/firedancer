#ifndef HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h
#define HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h

#include "../ballet/fd_ballet_base.h"

#define FD_VM_LOG_COLLECTOR_BYTES_LIMIT (10000UL)

/* The fd_vm_log_collector_t is used within the vm for logging of text/bytes from within programs. 
 * The logger can collect up to FD_VM_LOG_COLLECTOR_BYTES_LIMIT bytes of log data, beyond which the
 * log is truncated. The log data collected is but
 */
struct fd_vm_log_collector {
  uchar buf[ FD_VM_LOG_COLLECTOR_BYTES_LIMIT ];
  ulong buf_used;
};
typedef struct fd_vm_log_collector fd_vm_log_collector_t;

/* Initializes a log collector */
fd_vm_log_collector_t * 
fd_vm_log_collector_init( fd_vm_log_collector_t * log_collector );

/* Appends a log message of some length to the log collector, truncating if the logger is already
 * full.
 */
void
fd_vm_log_collector_log( fd_vm_log_collector_t *  log_collector, 
                         char *                   msg, 
                         ulong                    msg_len );

#endif /* HEADER_fd_src_ballet_runtime_vm_fd_log_collector_h */
