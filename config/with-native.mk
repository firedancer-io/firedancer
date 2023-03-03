CPPFLAGS+=-march=native

CPUFLAGS:=$(shell grep -m1 flags /proc/cpuinfo | head -n1 | awk '{$$1=$$2=""; print $$0}' | tr ' ' '\n')

ifeq "$(shell uname -m)" "x86_64"
FD_HAS_X86:=1
FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
CPPFLAGS+=-fomit-frame-pointer -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1
endif

# CPU features

ifneq ($(filter sse,$(CPUFLAGS)),)
$(info Detected FD_HAS_SSE)
FD_HAS_SSE:=1
CPPFLAGS+=-DFD_HAS_SSE=1 -mfpmath=sse
endif

ifneq ($(filter avx2,$(CPUFLAGS)),)
$(info Detected FD_HAS_AVX)
FD_HAS_AVX:=1
CPPFLAGS+=-DFD_HAS_AVX=1
endif

ifneq ($(filter sha_ni,$(CPUFLAGS)),)
$(info Detected FD_SHA256_CORE_IMPL)
CPPFLAGS+=-DFD_SHA256_CORE_IMPL=1
else
CPPFLAGS+=-DFD_SHA256_CORE_IMPL=0
endif

