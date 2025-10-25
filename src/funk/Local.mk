ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_funk_base.h fd_funk_txn.h fd_funk_rec.h fd_funk_val.h fd_funk.h)
$(call add-objs,fd_funk_base fd_funk_txn fd_funk_rec fd_funk_val fd_funk,fd_funk)
$(call make-unit-test,test_funk_base,test_funk_base,fd_funk fd_util)
$(call run-unit-test,test_funk_base)
$(call make-unit-test,test_funk,test_funk,fd_funk fd_util)
$(call run-unit-test,test_funk)
ifdef FD_HAS_HOSTED
$(call make-unit-test,bench_funk_index,bench_funk_index,fd_funk fd_util)
endif
endif
