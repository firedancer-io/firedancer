ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
ifdef FD_HAS_X86
$(call make-bin,fd_vm_jitproto,fd_vm_jitproto,fd_disco fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
endif
endif
endif
endif
