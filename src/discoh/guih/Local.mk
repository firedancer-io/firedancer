ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_guih.h fd_guih_printf.h fd_guih_metrics.h)
$(call add-objs,fd_guih fd_guih_printf fd_guih_tile generated/http_import_dist,fd_discoh)
$(OBJDIR)/obj/discoh/guih/fd_guih_tile.o: book/public/fire.svg
endif

src/discoh/guih/dist_cmp/%.zst: src/discoh/guih/dist/% $(OBJDIR)/bin/fd_zstd_pack
	mkdir -p $(@D);
	$(OBJDIR)/bin/fd_zstd_pack 19 $< $@;
	$(TOUCH) $@;

src/discoh/guih/dist_cmp/%.gz: src/discoh/guih/dist/% $(OBJDIR)/bin/fd_gzip_pack
	mkdir -p $(@D);
	$(OBJDIR)/bin/fd_gzip_pack 9 $< $@;
	$(TOUCH) $@;

FD_GUIH_FRONTEND_FILES := $(shell $(FIND) src/discoh/guih/dist -type f)
FD_GUIH_FRONTEND_GZ_FILES := $(patsubst src/discoh/guih/dist/%, src/discoh/guih/dist_cmp/%.gz, $(FD_GUIH_FRONTEND_FILES))
FD_GUIH_FRONTEND_ZST_FILES := $(patsubst src/discoh/guih/dist/%, src/discoh/guih/dist_cmp/%.zst, $(FD_GUIH_FRONTEND_FILES))

$(OBJDIR)/obj/discoh/guih/generated/http_import_dist.o: $(FD_GUIH_FRONTEND_GZ_FILES) $(FD_GUIH_FRONTEND_ZST_FILES)
endif
