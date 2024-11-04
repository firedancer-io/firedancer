BUILDDIR?=linux/gcc/arm_n1

# This machine target is compatible with generic ARMv8.4-A server CPUs
# like Neoverse V1 (ca 2020-Sep) or AWS Graviton3.

# Experimental! Firedancer does not yet support Arm CPU, expect bugs.

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-gcc.mk
include config/extra/with-arm.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-threads.mk

CCPFLAGS+=-mcpu=neoverse-n1
CPPFLAGS+=-DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1

FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
FD_HAS_ALLOCA:=1
