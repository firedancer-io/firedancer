ifdef FD_HAS_HOSTED
ifdef FD_HAS_BLST # the votor tile IS alpenglow
$(call add-hdrs,fd_votor_tile.h)
$(call add-objs,fd_votor_tile,fd_discof)
$(call make-unit-test,test_votor_tile,test_votor_tile,fd_discof ag_alpenglow fd_choreo fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_votor_tile)
endif
endif
