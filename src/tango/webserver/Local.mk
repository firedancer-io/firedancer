ifdef FD_HAS_LIBMICROHTTP
$(call make-lib,fd_webserver)
$(call add-objs,fd_methods fd_quickstring fd_webserver json_lex,fd_webserver)
$(call add-hdrs,fd_webserver.h)
endif
