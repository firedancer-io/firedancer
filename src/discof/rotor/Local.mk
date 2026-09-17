$(call add-hdrs,fd_rotor_tile.h fd_chainer.h fd_schedulor.h fd_requestor.h fd_repair_stats.h)
$(call add-objs,fd_chainer fd_schedulor fd_requestor fd_repair_stats,fd_discof)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_rotor_tile,fd_discof)
$(call make-unit-test,test_chainer,test_chainer,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_chainer)
$(call make-unit-test,test_schedulor,test_schedulor,fd_discof fd_util)
$(call run-unit-test,test_schedulor)
$(call make-unit-test,test_requestor,test_requestor,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_requestor)
endif
