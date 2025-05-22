$(call add-hdrs,fd_sha1.h)
$(call add-objs,fd_sha1,fd_ballet)
$(call make-unit-test,test_sha1,test_sha1,fd_ballet fd_util)
$(call run-unit-test,test_sha1)
