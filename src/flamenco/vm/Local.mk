ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1

$(call add-hdrs,fd_vm_base.h fd_vm.h fd_vm_private.h) # FIXME: PRIVATE TEMPORARILY HERE DUE TO SOME MESSINESS IN FD_VM_SYSCALL.H
$(call add-objs,fd_vm fd_vm_interp fd_vm_disasm fd_vm_trace,fd_flamenco)

$(call add-hdrs,test_vm_util.h)
$(call add-objs,test_vm_util,fd_flamenco)

$(call make-bin,fd_vm_tool,fd_vm_tool,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))

# Unfortunately, the get_sysvar syscall handler depends on the funk database
$(call make-unit-test,test_vm_interp,test_vm_interp,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))

$(call make-unit-test,test_vm_base,test_vm_base,fd_flamenco fd_ballet fd_util)

$(call make-unit-test,test_vm_instr,test_vm_instr,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
$(call run-unit-test,test_vm_instr)

$(call run-unit-test,test_vm_base)
$(call run-unit-test,test_vm_interp)
endif
endif

$(call make-unit-test,test_pointer_chase,test_pointer_chase,fd_util)
$(call run-unit-test,test_pointer_chase)
endif
