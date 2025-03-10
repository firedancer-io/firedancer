ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX

$(call make-lib,fdctl_shared)

$(call add-hdrs,fd_cap_chk.h)
$(call add-hdrs,fd_sys_util.h)
$(call add-hdrs,fd_net_util.h)
$(call add-hdrs,fd_file_util.h)

$(call add-objs,fd_cap_chk,fdctl_shared)
$(call add-objs,fd_file_util,fdctl_shared)
$(call add-objs,fd_sys_util,fdctl_shared)
$(call add-objs,fd_net_util,fdctl_shared)

endif
endif
