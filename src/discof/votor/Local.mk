ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_votor_tile.h)
$(call add-objs,fd_votor_tile,fd_discof)
$(call make-unit-test,test_votor_tile,test_votor_tile,fd_discof fd_alpenglow fd_choreo fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_votor_tile)
endif
