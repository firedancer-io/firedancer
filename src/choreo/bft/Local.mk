ifdef FD_HAS_ROCKSDB

ifdef FD_HAS_INT128
$(call add-hdrs,fd_bft.h)
$(call add-objs,fd_bft,fd_choreo)
$(call make-unit-test,test_bft,test_bft,fd_choreo fd_flamenco fd_ballet fd_util)
endif

endif
