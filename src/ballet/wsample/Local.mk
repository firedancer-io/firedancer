$(call add-hdrs,fd_wsample.h)
$(call add-objs,fd_wsample,fd_ballet)
$(call make-unit-test,test_wsample,test_wsample,fd_ballet fd_util)
$(call run-unit-test,test_wsample,)
