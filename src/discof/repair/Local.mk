ifdef FD_HAS_HOSTED
$(call add-objs,fd_rserve_tile,fd_discof)
endif
$(call add-objs,fd_repair,fd_discof)
$(call add-hdrs,fd_repair.h)

$(call add-objs,fd_rserve,fd_discof)
$(call add-hdrs,fd_rserve.h)
$(call add-objs,fd_blockdb,fd_discof)
$(call add-hdrs,fd_blockdb.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_blockdb,test_blockdb,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_rserve_tile,test_rserve_tile,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_repair_serde,fuzz_repair_serde,fd_discof fd_disco fd_waltz fd_tango fd_ballet fd_util)
endif
