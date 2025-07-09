ifdef FD_HAS_INT128
$(call add-hdrs,fd_gui.h fd_gui_printf.h)
$(call add-objs,fd_gui fd_gui_printf fd_gui_tile generated/http_import_dist,fd_disco)
$(OBJDIR)/obj/disco/gui/fd_gui_tile.o: book/public/fire.svg
endif
