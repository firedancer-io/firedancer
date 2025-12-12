$(call add-hdrs,fd_sysvar.h fd_sysvar_base.h)
$(call add-objs,fd_sysvar,fd_flamenco)

$(call add-hdrs,fd_sysvar_cache.h)
$(call add-objs,fd_sysvar_cache fd_sysvar_cache_db,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_sysvar_clock.h)
$(call add-objs,fd_sysvar_clock,fd_flamenco)

$(call add-hdrs,fd_sysvar_epoch_rewards.h)
$(call add-objs,fd_sysvar_epoch_rewards,fd_flamenco)
endif

$(call add-hdrs,fd_sysvar_epoch_schedule.h)
$(call add-objs,fd_sysvar_epoch_schedule,fd_flamenco)

$(call add-hdrs,fd_sysvar_instructions.h)
$(call add-objs,fd_sysvar_instructions,fd_flamenco)

$(call add-hdrs,fd_sysvar_last_restart_slot.h)
$(call add-objs,fd_sysvar_last_restart_slot,fd_flamenco)

$(call add-hdrs,fd_sysvar_recent_hashes.h)
$(call add-objs,fd_sysvar_recent_hashes,fd_flamenco)

$(call add-hdrs,fd_sysvar_rent.h)
$(call add-objs,fd_sysvar_rent,fd_flamenco)
ifdef FD_HAS_DOUBLE
$(call add-objs,fd_sysvar_rent1,fd_flamenco)
endif

$(call add-hdrs,fd_sysvar_slot_hashes.h)
$(call add-objs,fd_sysvar_slot_hashes,fd_flamenco)

$(call add-hdrs,fd_sysvar_slot_history.h)
$(call add-objs,fd_sysvar_slot_history,fd_flamenco)

$(call add-hdrs,fd_sysvar_stake_history.h)
$(call add-objs,fd_sysvar_stake_history,fd_flamenco)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_sysvar,test_sysvar,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_sysvar)
endif
endif
