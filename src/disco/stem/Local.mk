ifdef FD_HAS_HOSTED
$(call make-unit-test,test_stem_sticky_poll,test_stem_sticky_poll,fd_disco fd_tango fd_util)
$(call run-unit-test,test_stem_sticky_poll)
ifdef FD_HAS_LINUX
$(call make-unit-test,test_stem_park,test_stem_park,fd_disco fd_tango fd_util)
$(call run-unit-test,test_stem_park)
endif
endif
