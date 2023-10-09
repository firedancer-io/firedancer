$(call add-hdrs, \
	fd_exec_epoch_ctx.h \
	fd_exec_instr_ctx.h \
 	fd_exec_slot_ctx.h \
	fd_exec_txn_ctx.h \
)

$(call add-objs, \
	fd_exec_epoch_ctx \
	fd_exec_instr_ctx \
 	fd_exec_slot_ctx \
	fd_exec_txn_ctx, \
	fd_flamenco \
)