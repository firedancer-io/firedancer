ifdef FD_HAS_IBVERBS
$(call add-hdrs,fd_ibverbs_mock.h)
$(call add-objs,fd_ibverbs_mock,fd_waltz)
endif
