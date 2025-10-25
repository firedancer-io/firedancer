ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_tower.h fd_tower_accts.h fd_tower_forks.h fd_tower_serde.h)
$(call add-objs,fd_tower,fd_choreo)
$(call add-objs,fd_tower_forks,fd_choreo)
$(call add-objs,fd_tower_serde,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_tower,test_tower,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
$(call make-unit-test,test_tower_serde,test_tower_serde,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
$(call run-unit-test,test_tower)
$(call run-unit-test,test_tower_serde)
endif
endif
endif
