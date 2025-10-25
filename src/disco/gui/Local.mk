ifdef FD_HAS_INT128
$(call add-hdrs,fd_gui.h fd_gui_printf.h fd_gui_peers.h)
$(call add-objs,fd_gui fd_gui_printf fd_gui_peers fd_gui_tile generated/http_import_dist,fd_disco)
$(OBJDIR)/obj/disco/gui/fd_gui_tile.o: book/public/fire.svg
$(call make-unit-test,test_live_table,test_live_table,fd_disco fd_util)
endif

src/disco/gui/dist_stable_cmp/%.zst: src/disco/gui/dist_stable/%
	mkdir -p $(@D);
	zstd -f -19 $< -o $@;

src/disco/gui/dist_stable_cmp/%.gz: src/disco/gui/dist_stable/%
	mkdir -p $(@D);
	gzip -f -c -9 $< > $@;

src/disco/gui/dist_alpha_cmp/%.zst: src/disco/gui/dist_alpha/%
	mkdir -p $(@D);
	zstd -f -19 $< -o $@;

src/disco/gui/dist_alpha_cmp/%.gz: src/disco/gui/dist_alpha/%
	mkdir -p $(@D);
	gzip -f -c -9 $< > $@;

src/disco/gui/dist_dev_cmp/%.zst: src/disco/gui/dist_dev/%
	mkdir -p $(@D);
	zstd -f -19 $< -o $@;

src/disco/gui/dist_dev_cmp/%.gz: src/disco/gui/dist_dev/%
	mkdir -p $(@D);
	gzip -f -c -9 $< > $@;

FD_GUI_FRONTEND_STABLE_FILES := $(shell find src/disco/gui/dist_stable -type f)
FD_GUI_FRONTEND_ALPHA_FILES := $(shell find src/disco/gui/dist_alpha -type f)
FD_GUI_FRONTEND_DEV_FILES := $(shell find src/disco/gui/dist_dev -type f)
FD_GUI_FRONTEND_STABLE_GZ_FILES := $(patsubst src/disco/gui/dist_stable/%, src/disco/gui/dist_stable_cmp/%.gz, $(FD_GUI_FRONTEND_STABLE_FILES))
FD_GUI_FRONTEND_STABLE_ZST_FILES := $(patsubst src/disco/gui/dist_stable/%, src/disco/gui/dist_stable_cmp/%.zst, $(FD_GUI_FRONTEND_STABLE_FILES))
FD_GUI_FRONTEND_ALPHA_GZ_FILES := $(patsubst src/disco/gui/dist_alpha/%, src/disco/gui/dist_alpha_cmp/%.gz, $(FD_GUI_FRONTEND_ALPHA_FILES))
FD_GUI_FRONTEND_ALPHA_ZST_FILES := $(patsubst src/disco/gui/dist_alpha/%, src/disco/gui/dist_alpha_cmp/%.zst, $(FD_GUI_FRONTEND_ALPHA_FILES))
FD_GUI_FRONTEND_DEV_GZ_FILES := $(patsubst src/disco/gui/dist_dev/%, src/disco/gui/dist_dev_cmp/%.gz, $(FD_GUI_FRONTEND_DEV_FILES))
FD_GUI_FRONTEND_DEV_ZST_FILES := $(patsubst src/disco/gui/dist_dev/%, src/disco/gui/dist_dev_cmp/%.zst, $(FD_GUI_FRONTEND_DEV_FILES))

$(OBJDIR)/obj/disco/gui/generated/http_import_dist.d: $(FD_GUI_FRONTEND_STABLE_GZ_FILES) $(FD_GUI_FRONTEND_STABLE_ZST_FILES) $(FD_GUI_FRONTEND_ALPHA_GZ_FILES) $(FD_GUI_FRONTEND_ALPHA_ZST_FILES) $(FD_GUI_FRONTEND_DEV_GZ_FILES) $(FD_GUI_FRONTEND_DEV_ZST_FILES)
