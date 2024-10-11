ifdef FD_HAS_INT128
$(call add-hdrs,fd_tower.h)
$(call add-objs,fd_tower,fd_choreo)
$(call make-unit-test,test_tower,test_tower,fd_choreo fd_flamenco fd_ballet fd_funk fd_util,$(SECP256K1_LIBS))
endif
