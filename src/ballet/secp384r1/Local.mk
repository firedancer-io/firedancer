ifdef FD_HAS_S2NBIGNUM
$(call add-hdrs,fd_secp384r1.h)
$(call add-objs,fd_secp384r1,fd_ballet)

$(call make-unit-test,test_secp384r1,test_secp384r1,fd_ballet fd_util)
$(call run-unit-test,test_secp384r1)
endif
