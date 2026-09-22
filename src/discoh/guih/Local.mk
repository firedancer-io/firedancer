ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_guih.h fd_guih_printf.h fd_guih_metrics.h)
$(call add-objs,fd_guih fd_guih_printf fd_guih_tile generated/http_import_dist,fd_discoh)
$(OBJDIR)/obj/discoh/guih/fd_guih_tile.o: book/public/fire.svg
endif

FD_GUIH_TOOL_OBJDIR := $(OBJDIR)/host/guih
FD_GUIH_ZSTD_INPUTS := src/ballet/zstd/fd_zstd_pack.c src/disco/gui/assets.mk src/third_party/zstd/Local.mk $(wildcard src/third_party/zstd/lib/*.h src/third_party/zstd/lib/common/* src/third_party/zstd/lib/compress/*)
FD_GUIH_GZIP_INPUTS := src/ballet/zstd/fd_gzip_pack.c src/disco/gui/assets.mk src/third_party/zlib/Local.mk $(wildcard src/third_party/zlib/*.c src/third_party/zlib/*.h)

$(FD_GUIH_TOOL_OBJDIR)/tool/fd_zstd_pack: $(FD_GUIH_ZSTD_INPUTS)
	$(Q)$(MAKE) --no-print-directory -f src/disco/gui/assets.mk CC='$(HOSTCC)' OBJDIR=$(FD_GUIH_TOOL_OBJDIR) Q=$(Q) FD_GUI_DIST=src/discoh/guih/dist ZSTD_DEFS='$(ZSTD_DEFS)' ZLIB_DEFS='$(ZLIB_DEFS)' $@

$(FD_GUIH_TOOL_OBJDIR)/tool/fd_gzip_pack: $(FD_GUIH_GZIP_INPUTS)
	$(Q)$(MAKE) --no-print-directory -f src/disco/gui/assets.mk CC='$(HOSTCC)' OBJDIR=$(FD_GUIH_TOOL_OBJDIR) Q=$(Q) FD_GUI_DIST=src/discoh/guih/dist ZSTD_DEFS='$(ZSTD_DEFS)' ZLIB_DEFS='$(ZLIB_DEFS)' $@

src/discoh/guih/dist_cmp/%.zst: src/discoh/guih/dist/% $(FD_GUIH_ZSTD_INPUTS) | $(FD_GUIH_TOOL_OBJDIR)/tool/fd_zstd_pack
	@printf 'ZSTD\t%s\n' $(notdir $@)
	$(Q)$(MKDIR) $(@D) && \
$(FD_GUIH_TOOL_OBJDIR)/tool/fd_zstd_pack 19 $< $@ && \
$(TOUCH) $@

src/discoh/guih/dist_cmp/%.gz: src/discoh/guih/dist/% $(FD_GUIH_GZIP_INPUTS) | $(FD_GUIH_TOOL_OBJDIR)/tool/fd_gzip_pack
	@printf 'GZIP\t%s\n' $(notdir $@)
	$(Q)$(MKDIR) $(@D) && \
$(FD_GUIH_TOOL_OBJDIR)/tool/fd_gzip_pack 9 $< $@ && \
$(TOUCH) $@

FD_GUIH_FRONTEND_FILES := $(call rfiles,src/discoh/guih/dist/)
FD_GUIH_FRONTEND_GZ_FILES := $(patsubst src/discoh/guih/dist/%, src/discoh/guih/dist_cmp/%.gz, $(FD_GUIH_FRONTEND_FILES))
FD_GUIH_FRONTEND_ZST_FILES := $(patsubst src/discoh/guih/dist/%, src/discoh/guih/dist_cmp/%.zst, $(FD_GUIH_FRONTEND_FILES))

$(OBJDIR)/obj/discoh/guih/generated/http_import_dist.o: $(FD_GUIH_FRONTEND_GZ_FILES) $(FD_GUIH_FRONTEND_ZST_FILES)
endif
