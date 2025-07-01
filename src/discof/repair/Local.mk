ifdef FD_HAS_INT128
$(call add-hdrs,fd_fec_chainer.h fd_forest.h fd_policy.h fd_repair.h)
$(call add-objs,fd_fec_chainer fd_forest fd_policy fd_repair fd_repair_tile,fd_discof)
$(call make-unit-test,test_fec_chainer,test_fec_chainer,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_forest,test_forest,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_policy,test_policy,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_repair,test_repair,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
endif
