ifdef FD_HAS_INT128
$(call add-objs,fd_blk_repair,fd_discof)
$(call add-objs,fd_fec_repair,fd_discof)
ifdef FD_HAS_SSE
$(call add-objs,fd_repair_tile,fd_discof)
endif
$(call make-unit-test,test_blk_repair,test_blk_repair,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_fec_repair,test_fec_repair,fd_discof fd_flamenco fd_ballet fd_util)
endif
