$(call add-hdrs,fd_txn.h )
$(call add-objs,fd_txn_parse,fd_ballet)
$(call make-unit-test,test_txn_parse,test_txn_parse,fd_ballet fd_util)
$(call make-unit-test,test_txn,test_txn,fd_ballet fd_util)
$(call make-unit-test,test_compact_u16,test_compact_u16,fd_ballet fd_util)
$(call fuzz-test,fuzz_txn_parse,fuzz_txn_parse,fd_ballet fd_util)

$(call run-unit-test,test_txn_parse,)
$(call run-unit-test,test_txn,)
$(call run-unit-test,test_compact_u16,)

