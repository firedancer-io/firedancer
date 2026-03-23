CC:=hfuzz-clang
CXX:=hfuzz-clang++
LD:=hfuzz-clang++
CPPFLAGS+=-fno-omit-frame-pointer

# Explicit coverage flags to ensure both modes regardless of hfuzz-clang version.
# stack-depth OMITTED: uses __sancov_lowest_stack with initial-exec TLS,
# which sets DF_STATIC_TLS and crashes dlopen on glibc 2.34.
CPPFLAGS+=-fsanitize-coverage=trace-pc-guard,inline-8bit-counters,pc-table,trace-cmp,trace-div,indirect-calls,trace-gep
LDFLAGS+=-fsanitize-coverage=trace-pc-guard,inline-8bit-counters,pc-table,trace-cmp,trace-div,indirect-calls,trace-gep

FD_HAS_FUZZ:=1

# The patched honggfuzz (master-patches) instrument.c references
# hfuzz_metrics_register_module and hfuzz_metrics_register_pc_table.
# hfuzz-clang++ links libhfuzz.a (with --whole-archive) AFTER all user
# libraries.  The stubs live in libfd_util.a but nothing references them
# until libhfuzz.a is processed, so --undefined forces the linker to
# pull them from the archive on the first pass.
LDFLAGS+=-Wl,--undefined=hfuzz_metrics_register_module
LDFLAGS+=-Wl,--undefined=hfuzz_metrics_register_pc_table
