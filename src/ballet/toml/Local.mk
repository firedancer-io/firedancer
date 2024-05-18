$(call add-hdrs,fd_toml.h)
$(call add-objs,fd_toml,fd_ballet)
$(call make-fuzz-test,fuzz_toml,fuzz_toml,fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_toml,test_toml,fd_ballet fd_util)
$(call run-unit-test,test_toml)
endif
