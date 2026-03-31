ifdef FD_HAS_INT128

$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_stake_rewards.h)
$(call add-objs,fd_stake_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_epoch_boundary,test_epoch_boundary,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_epoch_boundary)
endif

endif
