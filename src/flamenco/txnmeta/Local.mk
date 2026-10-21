$(call add-hdrs,fd_txn_meta.h)
$(call add-objs,fd_txn_meta,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_txn_meta,test_txn_meta,fd_flamenco fd_disco fd_ballet fd_util)
$(call run-unit-test,test_txn_meta)

$(call make-fuzz-test,fuzz_txn_meta,fuzz_txn_meta,fd_flamenco fd_disco fd_ballet fd_util)
endif
