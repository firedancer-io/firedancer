$(call add-hdrs,fd_microblock.h)
$(call add-objs,fd_microblock,fd_ballet)

$(call make-unit-test,test_microblock,test_microblock,fd_ballet fd_util)
$(call make-unit-test,test_block_poh,test_block_poh,fd_ballet fd_util)
