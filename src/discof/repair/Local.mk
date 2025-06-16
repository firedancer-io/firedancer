ifdef FD_HAS_INT128
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_repair,fd_discof)
$(call add-objs,fd_fec_chainer,fd_discof)
$(call make-unit-test,test_repair,test_repair,fd_discof fd_flamenco fd_ballet fd_util)
endif
