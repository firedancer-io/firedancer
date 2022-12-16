$(call make-unit-test,test_compute_budget_program,test_compute_budget_program,fd_ballet fd_util)
$(call make-unit-test,test_est_tbl,test_est_tbl,fd_ballet fd_util)
$(call run-unit-test,test_compute_budget_program,)
$(call run-unit-test,test_est_tbl,)
