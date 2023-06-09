CC:=afl-clang-fast
CXX:=afl-clang-fast++
LD:=afl-clang-fast++

CPPFLAGS+=-fsanitize=fuzzer-no-link,address -march=native
LDFLAGS+=-fsanitize=fuzzer,address

FD_HAS_MAIN:=0
