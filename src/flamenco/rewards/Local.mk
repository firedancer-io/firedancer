$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_stake_rewards.h)
$(call add-objs,fd_stake_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_stake_rewards_forks,fuzz_stake_rewards_forks,fd_flamenco fd_ballet fd_util)
endif
