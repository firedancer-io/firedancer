$(call add-hdrs,fd_genesis_create.h)
$(call add-objs,fd_genesis_create,fd_flamenco)

$(call add-hdrs,fd_genesis_parse.h)
$(call add-objs,fd_genesis_parse,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_genesis_create,test_genesis_create,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_genesis_create)

$(call make-fuzz-test,fuzz_genesis_parse,fuzz_genesis_parse,fd_flamenco fd_ballet fd_util)
endif
