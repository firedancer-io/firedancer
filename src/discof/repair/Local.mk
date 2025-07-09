ifdef FD_HAS_INT128
$(call add-objs,fd_fec_repair,fd_discof)
$(call add-objs,fd_fec_chainer,fd_discof)
$(call add-objs,fd_repair_tile,fd_discof)
$(call make-unit-test,test_fec_repair,test_fec_repair,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_fec_chainer,test_fec_chainer,fd_discof fd_flamenco fd_ballet fd_util)
endif
