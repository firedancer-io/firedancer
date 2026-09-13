ifdef FD_HAS_HOSTED
$(call make-unit-test,test_stem_sticky_poll,test_stem_sticky_poll,fd_disco fd_tango fd_util)
$(call run-unit-test,test_stem_sticky_poll)
endif
