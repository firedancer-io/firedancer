ifdef FD_HAS_INT128
$(call add-hdrs,fd_repair.h fd_recorder.h)
$(call add-objs,fd_repair fd_recorder,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_repair,test_repair,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_recorder,test_recorder,fd_flamenco fd_ballet fd_util)
endif
endif
