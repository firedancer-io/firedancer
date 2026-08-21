$(call add-objs,fd_chainer,fd_discof)
$(call add-hdrs,fd_chainer.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_chainer,test_chainer,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_chainer)
endif
