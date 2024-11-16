# Switches linker to 'mold'
# https://github.com/rui314/mold
#
# This linker is usually much faster than the default linker when working
# with large binaries (Rust projects, fdctl, etc.)

MOLD_LDFLAGS=-fuse-ld=mold

ifdef FD_USING_GCC
ifeq ($(shell test $(FD_COMPILER_MAJOR_VERSION) -lt 12 && echo 1),1)
# Old GCC versions don't recognize mold
MOLD_LDFLAGS=-B$(shell which mold)
endif
endif

LDFLAGS+=$(MOLD_LDFLAGS)
