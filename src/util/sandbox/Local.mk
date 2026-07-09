ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_ARCH_SUPPORTS_SANDBOX
$(call add-hdrs,fd_sandbox.h)
$(call add-objs,fd_sandbox,fd_util)
$(call make-unit-test,test_sandbox,test_sandbox,fd_util)
endif
ifdef FD_HAS_X86
$(call add-hdrs,fd_pkeys.h)
$(call add-objs,fd_pkeys,fd_util)
$(call make-unit-test,test_pkeys,test_pkeys,fd_util)
$(call run-unit-test,test_pkeys)
endif
endif
endif
