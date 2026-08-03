ifdef FD_HAS_HOSTED
$(call add-objs,fd_dedup_tile,fd_disco)
# $(call make-unit-test,test_dedup,test_dedup,fd_disco fd_tango fd_util)
$(call make-unit-test,test_dedup_tile,test_dedup_tile,fd_disco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_dedup_tile)
endif
