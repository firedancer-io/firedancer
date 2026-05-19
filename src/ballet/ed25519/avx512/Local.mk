$(call add-hdrs,fd_r52x5_inl.h fd_r52x5_ge.h)
ifdef FD_HAS_AVX512
$(call make-unit-test,test_r52x5,test_r52x5,fd_ballet fd_util)
$(call run-unit-test,test_r52x5)
endif
