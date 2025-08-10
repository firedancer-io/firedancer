ifdef FD_HAS_INT128
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_repair,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_repair,test_repair,fd_flamenco fd_ballet fd_util)
endif
endif
