ifdef FD_HAS_INT128
$(call add-hdrs,fd_leaders.h fd_multi_epoch_leaders.h)
$(call add-objs,fd_leaders fd_multi_epoch_leaders,fd_flamenco)
$(call make-unit-test,test_leaders,test_leaders,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_multi_leaders,test_multi_leaders,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_leaders,)
$(call run-unit-test,test_multi_leaders)
endif
