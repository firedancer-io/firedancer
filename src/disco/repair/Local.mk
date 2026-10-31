$(call add-hdrs,fd_repair.h fd_repair_serde.h fd_repair_strat.h)
$(call add-objs,fd_repair fd_repair_serde fd_repair_strat,fd_disco)
$(call add-hdrs,fd_rotor_tile.h)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_rotor_tile,fd_disco)
$(call add-objs,fd_rserve_tile,fd_disco)
endif
$(call add-objs,fd_rserve,fd_disco)
$(call add-hdrs,fd_rserve.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_fd_repair,test_fd_repair,fd_disco fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_fd_repair)
$(call make-unit-test,test_fd_repair_serde,test_fd_repair_serde,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_fd_repair_serde)
$(call make-unit-test,test_fd_repair_strat,test_fd_repair_strat,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_fd_repair_strat)
$(call make-unit-test,test_blockdb,test_blockdb,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_rserve_tile,test_rserve_tile,fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_repair_serde,fuzz_repair_serde,fd_disco fd_waltz fd_tango fd_ballet fd_util)
endif
