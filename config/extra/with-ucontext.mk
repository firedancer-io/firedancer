# ucontext.h is no longer part of POSIX and thus considered an extra.
# It is still part of glibc, but not musl libc.

# Hacky: If libucontext is installed, use that instead.
ifeq ($(shell test -f /lib/libucontext.a && echo 1),1)
  LDFLAGS+=-lucontext
endif

FD_HAS_UCONTEXT:=1
CPPFLAGS+=-DFD_HAS_UCONTEXT=1
