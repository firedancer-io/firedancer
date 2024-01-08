ifneq "$(FD_USING_CLANG)" "1"
$(error llvm-cov requires clang)
endif

FD_HAS_COVERAGE:=1

CPPFLAGS+=-DFD_HAS_COVERAGE=1
CPPFLAGS+=-fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping

