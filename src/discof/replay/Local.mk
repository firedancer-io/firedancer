ifdef FD_HAS_INT128
$(call add-objs,fd_fec_chainer,fd_replay)
ifdef FD_HAS_SSE
$(call add-objs,fd_replay_tile fd_replay,fd_discof)
$(call make-unit-test,test_replay,test_replay,fd_discof fd_disco fd_flamenco fd_tango fd_util)
$(call make-unit-test,test_fec_chainer,test_fec_chainer,fd_discof fd_flamenco fd_ballet fd_util)
endif
