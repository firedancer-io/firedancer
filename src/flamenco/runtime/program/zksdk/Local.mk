ifdef FD_HAS_INT128
$(call add-hdrs,fd_zksdk.h)
$(call add-objs,fd_zksdk,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_zksdk,test_zksdk,fd_flamenco fd_funk fd_ballet fd_util)
endif
endif
