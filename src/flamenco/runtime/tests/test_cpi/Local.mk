ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1

$(call add-hdrs,fd_vm_cpi_test_utils.h)
$(call add-objs,fd_vm_cpi_test_utils,fd_flamenco)

endif
endif