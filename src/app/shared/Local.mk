ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA

$(call add-hdrs,fd_cap_chk.h)
$(call add-hdrs,fd_file_util.h)

$(call add-objs,fd_cap_chk,fdctl_shared)
$(call add-objs,fd_file_util,fdctl_shared)

endif
endif
endif
