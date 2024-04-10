ifdef FD_HAS_INT128
$(call add-hdrs,fd_sysvar_cache.h)
$(call add-objs,fd_sysvar_cache,fd_flamenco)

$(call add-hdrs,fd_sysvar_clock.h)
$(call add-objs,fd_sysvar_clock,fd_flamenco)

$(call add-hdrs,fd_sysvar_epoch_schedule.h)
$(call add-objs,fd_sysvar_epoch_schedule,fd_flamenco)
$(call make-unit-test,test_sysvar_epoch_schedule,test_sysvar_epoch_schedule,fd_flamenco fd_util)
$(call run-unit-test,test_sysvar_epoch_schedule)

$(call add-hdrs,fd_sysvar_instructions.h)
$(call add-objs,fd_sysvar_instructions,fd_flamenco)

$(call add-hdrs,fd_sysvar_rent.h)
$(call add-objs,fd_sysvar_rent,fd_flamenco)
$(call make-unit-test,test_sysvar_rent,test_sysvar_rent,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_sysvar_rent)

$(call add-hdrs,fd_sysvar_slot_hashes.h)
$(call add-objs,fd_sysvar_slot_hashes,fd_flamenco)
endif
