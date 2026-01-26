ifdef FD_HAS_DOUBLE
$(call add-hdrs,fd_pack.h fd_est_tbl.h fd_compute_budget_program.h fd_microblock.h fd_pack_rebate_sum.h)
$(call add-objs,fd_pack,fd_ballet)
$(call add-objs,fd_pack_tile,fd_disco)
$(call add-objs,fd_pack_rebate_sum,fd_ballet)
$(call make-unit-test,test_compute_budget_program,test_compute_budget_program,fd_ballet fd_util)
$(call make-unit-test,test_est_tbl,test_est_tbl,fd_ballet fd_util)
$(call make-unit-test,test_pack_bitset,test_pack_bitset,fd_ballet fd_util)
$(call make-unit-test,test_chkdup,test_chkdup,fd_ballet fd_util)
$(call make-unit-test,test_tip_prog_blacklist,test_tip_prog_blacklist,fd_ballet fd_util)
$(call make-unit-test,test_pack_rebate_sum,test_pack_rebate_sum,fd_ballet fd_util)
$(call run-unit-test,test_compute_budget_program)
$(call run-unit-test,test_est_tbl)
$(call run-unit-test,test_pack_bitset)
$(call run-unit-test,test_chkdup)
$(call run-unit-test,test_tip_prog_blacklist)
$(call run-unit-test,test_pack_rebate_sum)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_compute_budget_program_parse,fuzz_compute_budget_program_parse,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_chkdup,fuzz_chkdup,fd_ballet fd_util)
$(call make-unit-test,test_pack,test_pack,fd_disco fd_ballet fd_util)
$(call run-unit-test,test_pack)
endif
endif
