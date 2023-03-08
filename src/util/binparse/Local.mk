$(call add-hdrs,fd_bin_parse.h, fd_slice.h)
$(call add-objs,fd_bin_parse fd_slice ,fd_util)
#$(call make-unit-test,test_cstr,test_cstr,fd_util)