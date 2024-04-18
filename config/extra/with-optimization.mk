ifeq ($(DISABLE_OPTIMIZATION),)
CPPFLAGS+=-O3 -ffast-math -fno-associative-math -fno-reciprocal-math -fomit-frame-pointer
CPPFLAGS+=-DFD_HAS_OPTIMIZATION=1 #-DFD_DEBUG_SBPF_TRACES
FD_HAS_OPTIMIZATION:=1
endif
RUST_PROFILE:=release
