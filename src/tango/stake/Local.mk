$(call add-hdrs,fd_stake.h)
$(call add-objs,fd_stake,fd_tango)
$(call make-unit-test,fd_stake,fd_stake,fd_tango fd_util)
$(call run-unit-test,fd_stake,)
