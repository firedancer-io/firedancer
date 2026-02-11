CC:=hfuzz-clang
CXX:=hfuzz-clang++
LD:=hfuzz-clang++
CPPFLAGS+=-fno-omit-frame-pointer

FD_HAS_FUZZ:=1

# The patched honggfuzz (master-patches) instrument.c references
# hfuzz_metrics_register_module and hfuzz_metrics_register_pc_table.
# hfuzz-clang++ links libhfuzz.a (with --whole-archive) AFTER all user
# libraries.  The stubs live in libfd_util.a but nothing references them
# until libhfuzz.a is processed, so --undefined forces the linker to
# pull them from the archive on the first pass.
LDFLAGS+=-Wl,--undefined=hfuzz_metrics_register_module
LDFLAGS+=-Wl,--undefined=hfuzz_metrics_register_pc_table
