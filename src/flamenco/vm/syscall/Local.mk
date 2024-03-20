ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_vm_syscall.h fd_vm_cpi.h)
$(call add-objs,fd_vm_syscall fd_vm_syscall_cpi fd_vm_syscall_crypto fd_vm_syscall_curve fd_vm_syscall_pda fd_vm_syscall_runtime fd_vm_syscall_util,fd_flamenco)

$(call make-unit-test,test_vm_syscalls,test_vm_syscalls,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_vm_syscall_cpi,test_vm_syscall_cpi,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_vm_syscall_curve,test_vm_syscall_curve,fd_flamenco fd_funk fd_ballet fd_util)

$(call run-unit-test,test_vm_syscalls)
$(call run-unit-test,test_vm_syscall_cpi)
$(call run-unit-test,test_vm_syscall_curve)
endif
endif
