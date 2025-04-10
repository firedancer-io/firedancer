ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_snp_tile,fd_disco)
endif
ifdef FD_HAS_HOSTED
endif
endif
