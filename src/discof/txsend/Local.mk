ifdef FD_HAS_HOSTED
$(call add-objs,fd_txsend_tile,fd_discof)
$(call make-unit-test,test_txsend_tile,test_txsend_tile,fd_discof fd_disco fd_choreo fd_flamenco fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_txsend_tile)
endif
