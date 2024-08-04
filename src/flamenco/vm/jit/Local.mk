ifdef FD_HAS_X86
$(call make-bin,fd_vm_jitproto,fd_vm_jitproto,fd_flamenco fd_disco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
endif
