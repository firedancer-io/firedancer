$(call add-hdrs,fd_mvcc.h)
$(call add-objs,fd_mvcc,fd_tango)
$(call make-unit-test,test_mvcc,test_mvcc,fd_tango fd_util)
$(call run-unit-test,test_mvcc,)
