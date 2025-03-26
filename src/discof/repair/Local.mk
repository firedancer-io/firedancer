ifdef FD_HAS_SSE
$(call add-objs,fd_repair_tile fd_repair fd_fec_chainer,fd_discof)
$(call make-unit-test,test_repair,test_repair,fd_discof fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_fec_chainer,test_fec_chainer,fd_discof fd_choreo fd_flamenco fd_ballet fd_util)
endif
