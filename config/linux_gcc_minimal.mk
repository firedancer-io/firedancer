BUILDDIR:=linux/gcc/minimal

include config/base.mk
include config/with-linux.mk
include config/with-gcc.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-hosted.mk
include config/with-openssl.mk

# Turn on POSIX style logging in this target to facilitate
# cross-platform development

CPPFLAGS+=-DFD_ENV_STYLE=0 -DFD_LOG_STYLE=0
