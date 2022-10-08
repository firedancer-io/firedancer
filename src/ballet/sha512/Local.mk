$(call add-hdrs,fd_sha512.h)
$(call add-objs,fd_sha512,fd_ballet)
$(call make-unit-test,test_sha512,test_sha512,fd_ballet fd_util)

