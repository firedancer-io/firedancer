$(call add-hdrs,fd_r43x6.h fd_r43x6_inl.h fd_r43x6_ge.h)
ifdef FD_HAS_AVX512
$(call add-objs,fd_r43x6 fd_r43x6_ge,fd_ballet)
$(call make-unit-test,test_r43x6,test_r43x6,fd_ballet fd_util)
$(call run-test,test_r43x6,)

#$(call make-unit-test,fd_r43x6_ge_smul_table,fd_r43x6_ge_smul_table,fd_ballet fd_util)
#$(call make-unit-test,fd_r43x6_ge_dmul_table,fd_r43x6_ge_dmul_table,fd_ballet fd_util)
endif
