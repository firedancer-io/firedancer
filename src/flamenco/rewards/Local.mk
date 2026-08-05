$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_stake_rewards.h)
$(call add-objs,fd_stake_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)
$(call make-unit-test,test_inflation_rate,test_inflation_rate,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_inflation_rate)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_stake_rewards_forks,fuzz_stake_rewards_forks,fd_flamenco fd_ballet fd_util)
endif
