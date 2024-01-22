$(call add-hdrs, \
	fd_block_info.h \
	fd_instr_info.h \
	fd_microblock_batch_info.h \
	fd_microblock_info.h \
	fd_txn_info.h \
)

$(call add-objs,fd_block_info,fd_flamenco)
$(call add-objs,fd_instr_info,fd_flamenco)
$(call add-objs,fd_microblock_batch_info,fd_flamenco)
$(call add-objs,fd_microblock_info,fd_flamenco)
$(call add-objs,fd_txn_info,,fd_flamenco)
