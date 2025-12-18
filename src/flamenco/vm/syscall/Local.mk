ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_vm_syscall.h fd_vm_syscall_macros.h fd_vm_cpi.h)
$(call add-objs,fd_vm_syscall fd_vm_syscall_cpi fd_vm_syscall_hash fd_vm_syscall_crypto fd_vm_syscall_curve fd_vm_syscall_pda fd_vm_syscall_runtime fd_vm_syscall_util,fd_flamenco)

$(call make-unit-test,test_vm_syscall_cpi,test_vm_syscall_cpi,fd_flamenco fd_funk fd_util fd_ballet)
$(call run-unit-test,test_vm_syscall_cpi)

ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_vm_syscalls,test_vm_syscalls,fd_flamenco fd_funk fd_util fd_ballet)
$(call run-unit-test,test_vm_syscalls)
$(call make-unit-test,test_vm_syscall_curve,test_vm_syscall_curve,fd_flamenco fd_funk fd_util fd_ballet)
$(call run-unit-test,test_vm_syscall_curve)
$(call make-unit-test,test_vm_increase_cpi_account_info_limit,test_vm_increase_cpi_account_info_limit,fd_flamenco fd_funk fd_util fd_ballet)
$(call run-unit-test,test_vm_increase_cpi_account_info_limit)
endif
endif
