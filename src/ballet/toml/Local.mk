$(call add-hdrs,fd_toml.h)
$(call add-objs,fd_toml,fd_ballet)
$(call make-fuzz-test,fuzz_toml,fuzz_toml,fd_ballet fd_util)
