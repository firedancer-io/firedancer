$(call add-hdrs,fd_r43x6.h)

ifdef FD_HAS_GFNI # TODO: ADD FLAGS FOR AVX-512
$(call make-unit-test,test_r43x6,test_r43x6,fd_ballet fd_util)
$(call run-test,test_r43x6,)
endif
