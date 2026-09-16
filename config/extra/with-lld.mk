# force lld (base.mk prefers mold when present)
comma:=,
LDFLAGS:=$(filter-out -B$(MOLD_DIR)/ -fuse-ld=% -Wl$(comma)-X,$(LDFLAGS)) -fuse-ld=lld
