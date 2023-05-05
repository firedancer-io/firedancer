$(call add-hdrs,fd_chacha20.h)
$(call add-objs,fd_chacha20_rng)

$(call make-unit-test,test_fd_chacha20_rng,test_fd_chacha20_rng,fd_ballet fd_util)
$(call run-unit-test,test_fd_chacha20_rng)