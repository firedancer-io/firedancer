ifeq ($(FD_DISABLE_OPTIMIZATION),)
CPPFLAGS+=-O3 -ffp-contract=off -fno-math-errno
CPPFLAGS+=-DFD_HAS_OPTIMIZATION=1
FD_HAS_OPTIMIZATION:=1
else
CPPFLAGS+=-O0 -ffp-contract=off -fno-math-errno
endif

RUST_PROFILE:=release-with-debug
