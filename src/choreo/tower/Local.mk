ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_tower.h)
$(call add-objs,fd_tower,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_tower,test_tower,fd_choreo fd_flamenco fd_funk fd_tango fd_ballet fd_util,$(SECP256K1_LIBS))
endif
endif
endif
