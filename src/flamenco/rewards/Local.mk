ifdef FD_HAS_INT128

$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_epoch_rewards.h)
$(call add-objs,fd_epoch_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)

$(call make-unit-test,test_epoch_rewards,test_epoch_rewards,fd_flamenco fd_util fd_ballet)
$(call run-unit-test,test_epoch_rewards)

endif
