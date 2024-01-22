include config/linux_gcc_x86_64.mk
BUILDDIR:=linux/gcc/x86_64_asan

FD_HAS_ASAN:=1
CPPFLAGS+=-DFD_HAS_ASAN=1

LDFLAGS+=-fsanitize=address,leak

CPPFLAGS+=-fsanitize=address,leak
