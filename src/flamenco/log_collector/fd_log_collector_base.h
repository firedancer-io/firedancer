#ifndef HEADER_fd_src_flamenco_log_collector_fd_log_collector_base_h
#define HEADER_fd_src_flamenco_log_collector_fd_log_collector_base_h

#include "../fd_flamenco_base.h"

/* Base definition for fd_log_collector_t.
   (This is needed to avoid circular dependencies) */

#define FD_LOG_COLLECTOR_MAX   (10000UL)  /* Max bytes of actual log messages before truncate:
                                             https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/log_collector.rs#L4 */
#define FD_LOG_COLLECTOR_PANIC_FILE_MAX (1024UL) /* Max bytes of a panic file name kept for the failure message */
#define FD_LOG_COLLECTOR_VM_ERR_MSG_MAX  (128UL) /* Max bytes of a VM access violation message */
#define FD_LOG_COLLECTOR_EXTRA (4000UL)   /* Large enough to cover worst cases:
                                             The serialization overhead is 2-3 bytes/log message,
                                             and realistically there can only be <800 messages.
                                             Moreover, we need extra space for possibly large
                                             vsnprintf, e.g. program_return().
                                             So, roughly, 2000 + 2000 = 4000 extra bytes. */
#define FD_LOG_COLLECTOR_PROTO_TAG (0x32) /* Tag for protobuf serialization */

struct fd_log_collector {
  ushort buf_sz;   /* The size of buf currently used, including serialization
                      overheads.  For example, if you need to copy all logs,
                      you should copy buf_sz bytes. */

  ushort log_sz;   /* The total bytes count of logs inserted, up to
                      FD_LOG_COLLECTOR_MAX.
                      This is only used to match Agave's behavior and
                      truncate logs when necessary. */

  uchar  warn;     /* Whether we truncated or not logs, to match Agave's
                      behavior. */

  uchar  disabled; /* Whether txn logs are disabled (1) or enabled (0). */

  /* The location the last sol_panic_ syscall of the transaction
     reported, for the program failure message: the file name, cut at
     FD_LOG_COLLECTOR_PANIC_FILE_MAX bytes, and the line and column.
     panic_file_sz is USHORT_MAX while no panic was reported. */
  ushort panic_file_sz;
  ulong  panic_line;
  ulong  panic_column;
  uchar  panic_file[ FD_LOG_COLLECTOR_PANIC_FILE_MAX ];

  /* The message of the last VM access violation of the transaction,
     as agave's EbpfError renders it; vm_err_msg_sz is USHORT_MAX while
     there is none. */
  ushort vm_err_msg_sz;
  char   vm_err_msg[ FD_LOG_COLLECTOR_VM_ERR_MSG_MAX ];

  /* Log buffer, serialized. */
  uchar  buf[ FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA ];
};
typedef struct fd_log_collector fd_log_collector_t;

FD_PROTOTYPES_BEGIN

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_log_collector_fd_log_collector_base_h */
