#include "fd_vm_log_collector.h"

fd_vm_log_collector_t *
fd_vm_log_collector_init( fd_vm_log_collector_t * log_collector ) {
  log_collector->buf_used = 0;
  return log_collector;
}

void
fd_vm_log_collector_log( fd_vm_log_collector_t *  log_collector,
                         char const *             msg,
                         ulong                    msg_len ) {
  ulong buf_used = log_collector->buf_used;
  ulong buf_remaining = FD_VM_LOG_COLLECTOR_BYTES_LIMIT - buf_used;

  if( buf_used==FD_VM_LOG_COLLECTOR_BYTES_LIMIT ) {
    // No more space, message is not copied into collector.
    return;
  }

  ulong bytes_to_copy = ( buf_remaining > msg_len ) ? msg_len : buf_remaining;
  log_collector->buf_used += bytes_to_copy;

  fd_memcpy( &log_collector->buf[ buf_used ], msg, bytes_to_copy );
}
