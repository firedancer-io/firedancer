ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_gui.h fd_gui_printf.h fd_gui_peers.h fd_gui_config_parse.h fd_gui_metrics.h fd_gui_store.h fd_gui_hist.h)
$(call add-objs,fd_gui fd_gui_printf fd_gui_peers fd_gui_config_parse fd_gui_tile fd_gui_store fd_gui_hist generated/http_import_dist,fd_disco)
$(OBJDIR)/obj/disco/gui/fd_gui_tile.o: book/public/fire.svg
$(call make-unit-test,test_live_table,test_live_table,fd_disco fd_util)
$(call make-unit-test,test_gui_geoip,test_gui_geoip,fd_util)
$(call make-fuzz-test,fuzz_config_parser,fuzz_config_parser,fd_disco fd_ballet fd_util)

$(call make-unit-test,test_gui_store,test_gui_store,fd_disco fd_util)
$(call run-unit-test,test_gui_store)
$(call make-unit-test,test_gui_hist_evict,test_gui_hist_evict,fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_gui_hist_evict)

src/disco/gui/dist_cmp/%.zst: src/disco/gui/dist/% $(OBJDIR)/bin/fd_zstd_pack
	mkdir -p $(@D);
	$(OBJDIR)/bin/fd_zstd_pack 19 $< $@;
	$(TOUCH) $@;

src/disco/gui/dist_cmp/%.gz: src/disco/gui/dist/% $(OBJDIR)/bin/fd_gzip_pack
	mkdir -p $(@D);
	$(OBJDIR)/bin/fd_gzip_pack 9 $< $@;
	$(TOUCH) $@;

FD_GUI_FRONTEND_FILES := $(shell $(FIND) src/disco/gui/dist -type f)
FD_GUI_FRONTEND_GZ_FILES := $(patsubst src/disco/gui/dist/%, src/disco/gui/dist_cmp/%.gz, $(FD_GUI_FRONTEND_FILES))
FD_GUI_FRONTEND_ZST_FILES := $(patsubst src/disco/gui/dist/%, src/disco/gui/dist_cmp/%.zst, $(FD_GUI_FRONTEND_FILES))

$(OBJDIR)/obj/disco/gui/generated/http_import_dist.o: $(FD_GUI_FRONTEND_GZ_FILES) $(FD_GUI_FRONTEND_ZST_FILES)
$(OBJDIR)/obj/disco/gui/fd_gui.o: src/disco/gui/dbip.bin.zst
endif
