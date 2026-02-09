/* fd_hfuzz_metrics_stubs.c provides weak no-op definitions for the
   hfuzz_metrics functions referenced by the patched honggfuzz
   instrument.c (master-patches branch).

   When building with hfuzz-clang/hfuzz-clang++, the compiler driver
   implicitly links libhfuzz.a into every binary.  The patched
   instrument.c within libhfuzz.a calls hfuzz_metrics_register_module
   and hfuzz_metrics_register_pc_table from the sanitizer coverage
   callbacks.  Without definitions for these symbols, the link fails.

   These weak stubs satisfy the linker when no real metrics
   implementation is present.  When a real implementation is linked
   (e.g. from solfuzz's hfuzz_metrics.c), the strong definitions
   there override these weak stubs. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uintptr_t pc;
  uintptr_t flags;
} fd_hfuzz_pc_entry_t;

__attribute__((weak)) void
hfuzz_metrics_register_module( char const * module_name,
                               uint32_t     guard_start,
                               uint32_t     guard_count ) {
  (void)module_name;
  (void)guard_start;
  (void)guard_count;
}

__attribute__((weak)) void
hfuzz_metrics_register_pc_table( char const *                 module_name,
                                 fd_hfuzz_pc_entry_t const *  pcs,
                                 size_t                       pc_count,
                                 uint32_t                     guard_start ) {
  (void)module_name;
  (void)pcs;
  (void)pc_count;
  (void)guard_start;
}
