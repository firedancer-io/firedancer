$(call add-hdrs,fd_slice.h)
$(call add-objs,fd_slice,fd_ballet)

$(call make-unit-test,test_slice,test_slice,fd_ballet fd_util)
$(call run-unit-test,test_slice)
