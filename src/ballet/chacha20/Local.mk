$(call add-hdrs,fd_chacha20.h)
$(call add-objs,fd_chacha20,fd_ballet)
$(call make-unit-test,test_chacha20,test_chacha20,fd_ballet fd_util)
$(call run-unit-test,test_chacha20)
