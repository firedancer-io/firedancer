ifdef FD_HAS_INT128
$(call add-hdrs,fd_rewards.h fd_rewards_types.h)
$(call add-objs,fd_rewards,fd_flamenco)
endif
