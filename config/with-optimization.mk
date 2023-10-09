ifeq ($(DISABLE_OPTIMIZATION),)
CPPFLAGS+=-O3 -ffast-math -fno-associative-math -fno-reciprocal-math  -fno-omit-frame-pointer
# CPPFLAGS+=-O0 -fno-omit-frame-pointer
CPPFLAGS+=-DFD_HAS_OPTIMIZATION=1 -DFD_DEBUG_SBPF_TRACES
FD_HAS_OPTIMIZATION:=1
endif
