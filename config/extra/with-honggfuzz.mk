CC:=hfuzz-clang
CXX:=hfuzz-clang++
# Use regular clang++ for linking to avoid embedding libhfuzz.a into shared libraries.
# The sanitizer coverage symbols will remain undefined and get resolved at runtime
# from libhfuzz.so (via LD_PRELOAD), allowing proper coverage registration with honggfuzz.
LD:=clang++
CPPFLAGS+=-fno-omit-frame-pointer
# Add coverage flags for linker since we're not using hfuzz-clang++ for LD
LDFLAGS+=-fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls

FD_HAS_FUZZ:=1
