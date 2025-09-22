ifeq ($(FD_DISABLE_OPTIMIZATION),)
CPPFLAGS+=-O3 -ffast-math -fno-associative-math -fno-reciprocal-math -fno-omit-frame-pointer
CPPFLAGS+=-DFD_HAS_OPTIMIZATION=1
FD_HAS_OPTIMIZATION:=1
else
CPPFLAGS+=-O0 -ffast-math -fno-associative-math -fno-reciprocal-math -fno-omit-frame-pointer
endif

RUST_PROFILE:=release-with-debug
