$(call add-hdrs,fd_dedup.h)
$(call add-objs,fd_dedup,fd_disco)
$(call make-bin,fd_dedup_tile,fd_dedup_tile,fd_disco fd_tango fd_util)
$(call make-unit-test,test_dedup,test_dedup,fd_disco fd_tango fd_util)
