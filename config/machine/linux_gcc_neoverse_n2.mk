BUILDDIR?=linux/gcc/neoverse_n2


include config/extra/with-gcc-pre.mk
include config/base.mk
include config/extra/with-gcc.mk
include config/extra/with-arm.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-threads.mk

CPPFLAGS+=-mcpu=neoverse-n2+lse+crypto+sha3
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 \
          -DFD_HAS_NEON=1 -DFD_HAS_SVE2=1 -DFD_HAS_ARM_SHA256=1 \
          -DFD_HAS_ARM_SHA512=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
FD_HAS_NEON:=1
FD_HAS_SVE2:=1
FD_HAS_ARM_SHA256:=1
FD_HAS_ARM_SHA512:=1
