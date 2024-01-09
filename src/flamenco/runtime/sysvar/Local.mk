ifdef FD_HAS_INT128
$(call add-hdrs,fd_sysvar_rent.h)
$(call add-objs,fd_sysvar_rent,fd_flamenco)
$(call make-unit-test,test_sysvar_rent,test_sysvar_rent,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_sysvar_rent)

$(call add-hdrs,fd_sysvar_epoch_schedule.h)
$(call add-objs,fd_sysvar_epoch_schedule,fd_flamenco)
$(call make-unit-test,test_sysvar_epoch_schedule,test_sysvar_epoch_schedule,fd_flamenco fd_util)
$(call run-unit-test,test_sysvar_epoch_schedule)
endif
