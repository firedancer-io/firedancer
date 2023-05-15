$(call add-hdrs,fd_chacha20.h)

$(call make-unit-test,test_fd_chacha20,test_fd_chacha20,fd_ballet fd_util)
$(call run-unit-test,test_fd_chacha20)