ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_votor_tile.h fd_votor_rooted.h)
$(call add-objs,fd_votor_tile,fd_discof)
$(call make-unit-test,test_votor_tile,test_votor_tile,fd_discof fd_disco fd_choreo fd_flamenco fd_quic fd_tls fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_votor_tile)
endif
