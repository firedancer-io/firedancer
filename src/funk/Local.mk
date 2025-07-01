ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_funk_base.h fd_funk_txn.h fd_funk_rec.h fd_funk_val.h fd_funk.h)
$(call add-objs,fd_funk_base fd_funk_txn fd_funk_rec fd_funk_val fd_funk,fd_funk)
$(call make-unit-test,test_funk_base,test_funk_base,fd_funk fd_util)
$(call run-unit-test,test_funk_base,)
$(call make-unit-test,test_funk,test_funk,fd_funk fd_util)
$(call run-unit-test,test_funk,)
$(call make-unit-test,test_funk_concur,test_funk_concur,fd_funk fd_util)
$(call run-unit-test,test_funk_concur,)
$(call make-unit-test,test_funk_concur2,test_funk_concur2,fd_funk fd_util)
$(call run-unit-test,test_funk_concur2,)
$(call make-unit-test,test_funk_rec,test_funk_rec test_funk_common,fd_funk fd_util)
$(call run-unit-test,test_funk_rec,)
$(call make-unit-test,test_funk_txn,test_funk_txn test_funk_common,fd_funk fd_util)
$(call run-unit-test,test_funk_txn,)
$(call make-unit-test,test_funk_val,test_funk_val test_funk_common,fd_funk fd_util)
$(call make-unit-test,test_funk_reconnect,test_funk_reconnect test_funk_common,fd_funk fd_util)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_funk_txn2,test_funk_txn2,fd_funk fd_util)
$(call run-unit-test,test_funk_txn2,)
$(call make-unit-test,bench_funk_index,bench_funk_index,fd_funk fd_util)
endif
endif
