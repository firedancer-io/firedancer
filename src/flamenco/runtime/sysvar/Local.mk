$(call add-hdrs, \
	fd_sysvar_clock.h \
	fd_sysvar.h \
	fd_sysvar_slot_history.h \
	fd_sysvar_slot_hashes.h \
	fd_sysvar_epoch_schedule.h \
	fd_sysvar_fees.h \
	fd_sysvar_rent.h \
	fd_sysvar_stake_history.h \
)

$(call add-objs,\
	fd_sysvar \
	fd_sysvar_clock \
	fd_sysvar_recent_hashes \
	fd_sysvar_slot_history \
	fd_sysvar_slot_hashes \
	fd_sysvar_epoch_schedule \
	fd_sysvar_fees \
	fd_sysvar_rent \
	fd_sysvar_stake_history,fd_flamenco\
)
