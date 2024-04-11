ifdef FD_HAS_INT128
$(call add-hdrs,fd_block_info.h)
$(call add-hdrs,fd_instr_info.h)
$(call add-hdrs,fd_microblock_batch_info.h)
$(call add-hdrs,fd_microblock_info.h)

$(call add-objs,fd_block_info,fd_flamenco)
$(call add-objs,fd_instr_info,fd_flamenco)
endif
