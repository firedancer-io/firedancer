ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_funkier_base.h fd_funkier_txn.h fd_funkier_rec.h fd_funkier_val.h fd_funkier_filemap.h fd_funkier.h)
$(call add-objs,fd_funkier_base fd_funkier_txn fd_funkier_rec fd_funkier_val fd_funkier_filemap fd_funkier,fd_funk)
$(call make-unit-test,test_funkier_base,test_funkier_base,fd_funk fd_util)
$(call make-unit-test,test_funkier,test_funkier,fd_funk fd_util)
$(call make-unit-test,test_funkier_concur,test_funkier_concur,fd_funk fd_util)
$(call make-unit-test,test_funkier_rec,test_funkier_rec test_funkier_common,fd_funk fd_util)
$(call make-unit-test,test_funkier_txn,test_funkier_txn test_funkier_common,fd_funk fd_util)
$(call make-unit-test,test_funkier_val,test_funkier_val test_funkier_common,fd_funk fd_util)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_funkier_txn2,test_funkier_txn2,fd_funk fd_util)
$(call make-unit-test,test_funkier_file,test_funkier_file,fd_funk fd_util)
endif
endif
