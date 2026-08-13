#ifndef HEADER_fd_src_disco_diag_fd_proc_interrupts_h
#define HEADER_fd_src_disco_diag_fd_proc_interrupts_h

/* fd_proc_interrupts.h parses /proc/interrupts and /proc/softirqs */

#include "../../util/tile/fd_tile.h"
#include "../metrics/generated/fd_metrics_enums.h"

#if FD_HAS_HOSTED

/* fd_proc_interrupts_read parses the content of /proc/interrupts in one
   pass.  opt_device_per_cpu, opt_tlb_per_cpu, and opt_loc_per_cpu are
   optional FD_TILE_MAX-element output arrays; NULL outputs are ignored.
   opt_device_per_cpu sums numbered (hardware) interrupt rows
   column-wise and excludes named system interrupts.  opt_tlb_per_cpu
   and opt_loc_per_cpu contain the respective named-row counters, or
   zero if the row was not found.

   Assumes that fd is a file descriptor of /proc/interrupts in procfs or
   a regular readable file.  Returns the number of CPUs found.  Silently
   skips over most parse errors.  If an unrecoverable parse error
   occurs, logs warning and returns 0.  Uses about 8 KiB of stack. */

ulong
fd_proc_interrupts_read( int     fd,
                         ulong * opt_device_per_cpu,
                         ulong * opt_tlb_per_cpu,
                         ulong * opt_loc_per_cpu );

/* fd_proc_stat_irq_ticks parses the per-CPU rows of /proc/stat and sums
   the irq, softirq and steal fields (columns 6, 7 and 8 after the cpuN
   token), which count clock ticks the CPU spent servicing hard IRQs,
   soft IRQs, or stolen by a hypervisor.  None of these are charged to
   the interrupted task's utime/stime (on kernels with
   CONFIG_IRQ_TIME_ACCOUNTING, which is near-universal in distro
   kernels; without it the counters undercount).  Assumes that fd is a
   file descriptor of /proc/stat in procfs or a regular readable file.
   Returns the number of CPUs found.  On return, per_cpu[i] contains
   the summed tick count for CPU i.  Silently skips over most parse
   errors.  If an unrecoverable parse error occurs, logs warning and
   returns 0. */

ulong
fd_proc_stat_irq_ticks( int   fd,
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

#endif /* HEADER_fd_src_disco_diag_fd_proc_interrupts_h */
