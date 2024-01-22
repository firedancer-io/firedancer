ifeq "$(FD_USING_CLANG)" "1"

FD_HAS_COVERAGE:=1

CPPFLAGS+=-DFD_HAS_COVERAGE=1
CPPFLAGS+=-fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping

else

$(warning "llvm-cov requested but not using Clang")

endif
