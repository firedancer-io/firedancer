$(call add-objs,fd_ipecho_tile,fd_discof)
$(call add-objs,fd_ipecho_client,fd_discof)
$(call add-objs,fd_ipecho_server,fd_discof)

$(call make-unit-test,test_ipecho_client,test_ipecho_client,fd_discof fd_disco fd_waltz fd_flamenco fd_ballet fd_tango fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_ipecho_client,fuzz_ipecho_client,fd_discof fd_flamenco fd_ballet fd_util)
endif
