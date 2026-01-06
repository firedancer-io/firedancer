ifdef FD_HAS_INT128

$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_epoch_rewards.h)
$(call add-objs,fd_epoch_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_rewards,test_rewards,fd_flamenco fd_funk fd_tango fd_ballet fd_util)
endif

$(call make-unit-test,test_epoch_rewards,test_epoch_rewards,fd_flamenco fd_util fd_ballet)
$(call run-unit-test,test_epoch_rewards)

endif
