ifneq "$(FD_USING_CLANG)" "1"
$(error llvm-cov requires clang)
endif

CPPFLAGS+=-fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping

