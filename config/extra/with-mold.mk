# force mold (base.mk picks it only for native builds and only when on PATH)
MOLD:=$(call which,mold)
ifeq ($(MOLD),)
$(error EXTRAS=mold: mold not found on PATH)
endif
MOLD_DIR:=$(firstword $(wildcard $(realpath $(dir $(realpath $(MOLD)))../libexec/mold)))
ifeq ($(MOLD_DIR),)
MOLD_DIR:=$(BASEDIR)/mold-ld
_:=$(shell mkdir -p $(MOLD_DIR) && ln -sfn $(realpath $(MOLD)) $(MOLD_DIR)/ld)
endif
comma:=,
LDFLAGS:=$(filter-out -B$(MOLD_DIR)/ -fuse-ld=% -Wl$(comma)-X,$(LDFLAGS)) $(if $(filter 0 1 2 3 4 5 6 7 8 9 10 11,$(CC_MAJOR_VERSION)),-B$(MOLD_DIR)/,-fuse-ld=mold) -Wl,-X
