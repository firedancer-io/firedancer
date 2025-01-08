BUILDDIR:=linux/gcc/power9

include config/base.mk
include config/extra/with-gcc.mk

CPPFLAGS:=-mcpu=power9
LDFLAGS:=-lm

ifneq ($(shell uname -m),ppc64le)
CROSS=1
endif

ifeq ($(CROSS),1)
CC:=powerpc64le-linux-gnu-gcc
CXX:=powerpc64le-linux-gnu-g++
LD:=powerpc64le-linux-gnu-g++
endif

include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-threads.mk

CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
