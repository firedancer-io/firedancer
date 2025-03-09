#ifndef HEADER_fd_src_disco_cswtch_fd_proc_interrupts_h
#define HEADER_fd_src_disco_cswtch_fd_proc_interrupts_h

/* fd_proc_interrupts.h parses /proc/interrupts and /proc/softirqs */

#include "../../util/tile/fd_tile.h"
#include "../metrics/generated/fd_metrics_enums.h"

#if FD_HAS_HOSTED

/* fd_proc_interrupts_colwise parses the content of /proc/interrupts.
   Sums up all device interrupt counters counters column-wise.  Ignores
   'system' interrupt counters such as NMI and timers.  Assumes that fd
   is a file descriptor of /proc/interrupts in procfs or a regular
   readable file.  Returns the number of CPUs found.  On return,
   per_cpu[i] for each i in [0,retval) contains the sum of all device
   interrupt counters for CPU i.  Silently skips over most parse errors.
   If an unrecoverable parse error occurs, logs warning and returns 0.
   Uses about 8 KiB of stack. */

ulong
fd_proc_interrupts_colwise( int   fd,
                            ulong per_cpu[ FD_TILE_MAX ] );

/* fd_proc_softirqs_sum parses the content of /proc/softirqs.  Sums up
   softirq counters by category.  Assumes that fd is a file descriptor
   of /proc/softirqs in procfs or a regular readable file.  Returns the
   number of CPUs found.  On return, per_cpu contains the sum of softirq
   counters per (CPU,soft-IRQ type).  Silently skips over most parse
   errors.  If an unrecoverable parse error occurs, logs warning and
   returns 0.  Uses about 8 KiB of stack. */

ulong
fd_proc_softirqs_sum( int   fd,
                      ulong per_cpu[ FD_METRICS_ENUM_SOFTIRQ_CNT ][ FD_TILE_MAX ] );

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_disco_cswtch_fd_proc_interrupts_h */
