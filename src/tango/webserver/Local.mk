ifdef FD_HAS_LIBMICROHTTP
$(call make-lib,fd_webserver)
$(call add-objs,fd_methods fd_quickstring fd_webserver json_lex,fd_flamenco)
$(call add-hdrs,fd_webserver.h)
$(call fuzz-test,fuzz_json_lex,fuzz_json_lex,fd_util fd_webserver)
endif
