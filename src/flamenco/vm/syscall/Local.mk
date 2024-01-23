ifdef FD_HAS_INT128
$(call add-objs,fd_vm_curve25519,fd_flamenco)
$(call make-unit-test,test_vm_syscalls_curve25519,test_vm_syscalls_curve25519,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_vm_syscalls_curve25519)
endif
