ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1

$(call add-hdrs,fd_vm_base.h fd_vm.h fd_vm_private.h) # FIXME: PRIVATE TEMPORARILY HERE DUE TO SOME MESSINESS IN FD_VM_SYSCALL.H
$(call add-objs,fd_vm fd_vm_interp fd_vm_disasm fd_vm_trace,fd_flamenco)

$(call make-bin,fd_vm_tool,fd_vm_tool,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))

$(call make-unit-test,test_vm_interp,test_vm_interp,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))

$(call make-unit-test,test_vm_base,test_vm_base,fd_flamenco fd_funk fd_ballet fd_util)

$(call run-unit-test,test_vm_base)
$(call run-unit-test,test_vm_interp)
endif
endif
endif