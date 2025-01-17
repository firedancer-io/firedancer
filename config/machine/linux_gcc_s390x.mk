BUILDDIR:=linux/gcc/s390x

include config/base.mk
include config/extra/with-gcc.mk

CPPFLAGS:=
LDFLAGS:=-lm

ifneq ($(shell uname -m),s390x)
CROSS=1
endif

ifeq ($(CROSS),1)
CC:=s390x-linux-gnu-gcc
CXX:=s390x-linux-gnu-g++
LD:=s390x-linux-gnu-g++
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
