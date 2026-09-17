ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_gui.h fd_gui_printf.h fd_gui_peers.h fd_gui_config_parse.h fd_gui_metrics.h fd_gui_store.h fd_gui_hist.h fd_gui_ema.h)
$(call add-objs,fd_gui fd_gui_printf fd_gui_peers fd_gui_config_parse fd_gui_tile fd_gui_store fd_gui_hist generated/http_import_dist,fd_disco)
$(OBJDIR)/obj/disco/gui/fd_gui_tile.o: book/public/fire.svg
$(call make-unit-test,test_live_table,test_live_table,fd_disco fd_choreo fd_flamenco fd_util)
$(call make-unit-test,test_gui_geoip,test_gui_geoip,fd_util)
$(call make-fuzz-test,fuzz_config_parser,fuzz_config_parser,fd_disco fd_ballet fd_util)
$(call make-unit-test,test_gui_config_parse,test_gui_config_parse,fd_disco fd_ballet fd_util)
$(call run-unit-test,test_gui_config_parse)

$(call make-unit-test,test_gui_store,test_gui_store,fd_disco fd_choreo fd_flamenco fd_util)
$(call run-unit-test,test_gui_store)
$(call make-unit-test,test_gui_hist_evict,test_gui_hist_evict,fd_disco fd_choreo fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_gui_hist_evict)
$(call make-unit-test,test_gui_tile,test_gui_tile,fd_disco fd_discof fd_choreo fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_gui_tile)

FD_GUI_FRONTEND_FILES := $(call rfiles,src/disco/gui/dist/)
FD_GUI_FRONTEND_CMP := $(patsubst src/disco/gui/dist/%,src/disco/gui/dist_cmp/%,$(FD_GUI_FRONTEND_FILES))
FD_GUI_FRONTEND_CMP_FILES := $(addsuffix .zst,$(FD_GUI_FRONTEND_CMP)) $(addsuffix .gz,$(FD_GUI_FRONTEND_CMP))

# stale compressed files (older than their input or any compressor input: packer sources, the
# vendored zstd/zlib sources and headers, their Local.mk, assets.mk; -nt is strict, as is make) are
# made by one source-only-prerequisite sub-make (assets.mk) so it starts in the first pass;
# http_import_dist.o depends on the phony job, not the files (their mtimes are cached before the
# job runs).  Each packer's newest input is found once: files newer than it must be newer than
# every input.
FD_GUI_ZSTD_INPUTS := src/ballet/zstd/fd_zstd_pack.c src/disco/gui/assets.mk src/third_party/zstd/Local.mk $(wildcard src/third_party/zstd/lib/*.h src/third_party/zstd/lib/common/* src/third_party/zstd/lib/compress/*)
FD_GUI_GZIP_INPUTS := src/ballet/zstd/fd_gzip_pack.c src/disco/gui/assets.mk src/third_party/zlib/Local.mk $(wildcard src/third_party/zlib/*.c src/third_party/zlib/*.h)
# member-list stamps (rewritten only on change): a removed source is an input change too
ifdef FD_STAMPS
$(shell mkdir -p $(OBJDIR)/tool)
$(call stamp,$(OBJDIR)/tool/zstd.mlist,$(filter %.c,$(FD_GUI_ZSTD_INPUTS)))
$(call stamp,$(OBJDIR)/tool/zlib.mlist,$(filter %.c,$(FD_GUI_GZIP_INPUTS)))
endif
FD_GUI_ZSTD_INPUTS += $(wildcard $(OBJDIR)/tool/zstd.mlist)
FD_GUI_GZIP_INPUTS += $(wildcard $(OBJDIR)/tool/zlib.mlist)
FD_GUI_STALE_CMP := $(shell zn=$$(ls -t $(FD_GUI_ZSTD_INPUTS) | head -1); gn=$$(ls -t $(FD_GUI_GZIP_INPUTS) | head -1); set -- $(FD_GUI_FRONTEND_CMP); for f in $(FD_GUI_FRONTEND_FILES); do [ $$1.zst -nt $$f ] && [ $$1.zst -nt $$zn ] || echo $$1.zst; [ $$1.gz -nt $$f ] && [ $$1.gz -nt $$gn ] || echo $$1.gz; shift; done)
.PHONY: gui-assets
ifneq ($(FD_GUI_STALE_CMP),)
gui-assets:
	$(Q)$(MAKE) --no-print-directory -f src/disco/gui/assets.mk CC='$(CC)' OBJDIR=$(OBJDIR) Q=$(Q) FD_GUI_DIST=src/disco/gui/dist ZSTD_DEFS='$(ZSTD_DEFS)' ZLIB_DEFS='$(ZLIB_DEFS)' TOOL_LDFLAGS='$(filter -fuse-ld=% -B% -static-libgcc,$(LDFLAGS))' $(FD_GUI_STALE_CMP)
else
gui-assets: ;
endif

$(OBJDIR)/obj/disco/gui/generated/http_import_dist.o: $(FD_GUI_FRONTEND_FILES) $(filter-out $(FD_GUI_STALE_CMP),$(FD_GUI_FRONTEND_CMP_FILES)) $(if $(FD_GUI_STALE_CMP),gui-assets)
$(OBJDIR)/obj/disco/gui/fd_gui.o: src/disco/gui/dbip.bin.zst
endif
