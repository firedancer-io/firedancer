$(call add-hdrs,fd_shred.h)
$(call add-objs,fd_shred,fd_ballet)
$(call make-unit-test,test_shred,test_shred,fd_ballet fd_util fd_reedsol)
$(call run-unit-test,test_shred,)
