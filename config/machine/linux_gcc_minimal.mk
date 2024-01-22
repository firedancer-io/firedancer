BUILDDIR:=linux/gcc/minimal

include config/base.mk
include config/extra/with-security.mk
include config/extra/with-gcc.mk
include config/extra/with-debug.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk

# Turn on POSIX style logging in this target to facilitate
# cross-platform development

CPPFLAGS+=-DFD_ENV_STYLE=0 -DFD_IO_STYLE=0 -DFD_LOG_STYLE=0 -D_XOPEN_SOURCE=700

