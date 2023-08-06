$(call add-hdrs,fd_stake.h)
$(call add-objs,fd_stake,fd_tango)
$(call make-unit-test,test_stake,test_stake,fd_tango fd_util)
$(call run-unit-test,test_stake,)
