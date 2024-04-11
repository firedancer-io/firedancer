ifdef FD_HAS_INT128
$(call add-objs,fd_vm_alt_bn128,fd_flamenco)
$(call add-objs,fd_vm_curve25519,fd_flamenco)
$(call add-objs,fd_vm_hashes,fd_flamenco)
$(call add-objs,fd_vm_poseidon,fd_flamenco)
$(call add-objs,fd_vm_secp256k1,fd_flamenco)

$(call make-unit-test,test_vm_syscalls_curve25519,test_vm_syscalls_curve25519,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_vm_syscalls_curve25519)
endif
