ifdef FD_HAS_INT128
$(call add-hdrs,fd_gui.h fd_gui_printf.h)
$(call add-objs,fd_gui fd_gui_printf fd_gui_tile generated/http_import_dist,fd_disco)
$(OBJDIR)/obj/disco/gui/fd_gui_tile.o: book/public/fire.svg
$(call make-unit-test,test_live_table,test_live_table,fd_disco fd_util)
endif
