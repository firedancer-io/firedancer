ifdef FD_HAS_INT128
$(call add-hdrs,fd_genesis_create.h)
$(call add-objs,fd_genesis_create,fd_flamenco)
$(call make-unit-test,test_genesis_create,test_genesis_create,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_genesis_create)
endif
