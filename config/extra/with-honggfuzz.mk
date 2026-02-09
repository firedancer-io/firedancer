CC:=hfuzz-clang
CXX:=hfuzz-clang++
LD:=hfuzz-clang++
CPPFLAGS+=-fno-omit-frame-pointer

FD_HAS_FUZZ:=1

# The patched honggfuzz (master-patches) instrument.c references
# hfuzz_metrics_register_module and hfuzz_metrics_register_pc_table.
# hfuzz-clang++ links libhfuzz.a (with --whole-archive) AFTER all user
# libraries, so these stubs must also be whole-archive linked to ensure
# the definitions are in the symbol table before instrument.o needs them.
LDFLAGS+=-Wl,--whole-archive -lfd_hfuzz_stubs -Wl,--no-whole-archive
