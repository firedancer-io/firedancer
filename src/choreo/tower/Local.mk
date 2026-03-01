$(call add-hdrs,fd_tower.h fd_tower_blocks.h fd_tower_serdes.h fd_tower_stakes.h fd_tower_voters.h)
$(call add-objs,fd_tower,fd_choreo)
$(call add-objs,fd_tower_blocks,fd_choreo)
$(call add-objs,fd_tower_serdes,fd_choreo)
$(call add-objs,fd_tower_stakes,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_tower,test_tower,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
$(call make-unit-test,test_tower_blocks,test_tower_blocks,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
$(call make-unit-test,test_tower_serdes,test_tower_serdes,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
$(call run-unit-test,test_tower)
$(call run-unit-test,test_tower_blocks)
$(call run-unit-test,test_tower_serdes)
$(call make-fuzz-test,fuzz_tower_serdes,fuzz_tower_serdes,fd_choreo fd_flamenco fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
endif
