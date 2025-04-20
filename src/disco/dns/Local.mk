ifdef FD_HAS_SSE
ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_dns_tile.h)
$(call add-objs,fd_dns_tile,fd_waltz)
endif
endif
