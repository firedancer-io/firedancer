ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
ifdef FD_HAS_X86
$(call add-hdrs,fd_jit.h)
$(call add-objs,fd_jit fd_jit_compiler,fd_flamenco)
$(call make-unit-test,test_jit_dasm,test_jit_dasm,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_jit_dasm)
endif
endif
endif
