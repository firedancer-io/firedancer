ifdef FD_HAS_INT128

$(call add-hdrs,fd_rewards_base.h)

$(call add-hdrs,fd_stake_rewards.h)
$(call add-objs,fd_stake_rewards,fd_flamenco)

$(call add-hdrs,fd_rewards.h)
$(call add-objs,fd_rewards,fd_flamenco)

endif
