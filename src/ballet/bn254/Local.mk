ifneq ($(FD_HAS_LIBFF),)

$(call add-hdrs,fd_bn254.h)
$(call add-objs,fd_bn254,fd_ballet)
$(call make-unit-test,test_bn254,test_bn254,fd_ballet fd_util)

else

$(warning bn254 disabled due to lack of libff)

endif
