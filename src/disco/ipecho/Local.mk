ifdef FD_HAS_HOSTED
$(call add-objs,fd_ipecho_tile,fd_disco)
$(call add-objs,fd_ipecho_client,fd_disco)
$(call add-objs,fd_ipecho_server,fd_disco)
$(call add-objs,fd_ipecho_server_port_check,fd_disco)

$(call make-unit-test,test_ipecho_client,test_ipecho_client,fd_disco fd_waltz fd_flamenco fd_ballet fd_tango fd_util)
$(call make-unit-test,test_ipecho_server,test_ipecho_server,fd_disco fd_waltz fd_flamenco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_ipecho_server)

$(call make-fuzz-test,fuzz_ipecho_client,fuzz_ipecho_client,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ipecho_server,fuzz_ipecho_server,fd_disco fd_flamenco fd_ballet fd_tango fd_util)
endif
