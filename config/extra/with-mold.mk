# Switches linker to 'mold'
# https://github.com/rui314/mold
#
# This linker is usually much faster than the default linker when working
# with large binaries (Rust projects, fdctl, etc.)

MOLD_LDFLAGS=-fuse-ld=mold

ifdef FD_USING_GCC
ifeq ($(shell test $(FD_COMPILER_MAJOR_VERSION) -lt 12 && echo 1),1)
# gcc <12 has no -fuse-ld=mold; -B needs a directory whose ld is mold
MOLD_DIR:=$(firstword $(wildcard $(realpath $(dir $(realpath $(shell which mold)))../libexec/mold)))
ifeq ($(MOLD_DIR),)
MOLD_DIR:=$(BASEDIR)/mold-ld
_:=$(shell mkdir -p $(MOLD_DIR) && ln -sfn $(realpath $(shell which mold)) $(MOLD_DIR)/ld)
endif
MOLD_LDFLAGS=-B$(MOLD_DIR)/
endif
endif

# base.mk may already have picked lld; a later -B would lose to -fuse-ld=lld
LDFLAGS:=$(filter-out -fuse-ld=%,$(LDFLAGS)) $(MOLD_LDFLAGS)
