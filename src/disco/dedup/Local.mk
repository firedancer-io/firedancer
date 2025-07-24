ifdef FD_HAS_ALLOCA
$(call add-objs,fd_dedup_tile,fd_disco)
# $(call make-unit-test,test_dedup,test_dedup,fd_disco fd_tango fd_util)
endif
