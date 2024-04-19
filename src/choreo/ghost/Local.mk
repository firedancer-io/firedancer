ifdef FD_HAS_ROCKSDB

ifdef FD_HAS_INT128
$(call add-hdrs,fd_ghost.h)
$(call add-objs,fd_ghost,fd_choreo)
$(call make-unit-test,test_ghost,test_ghost,fd_choreo fd_flamenco fd_ballet fd_util)
endif

endif
