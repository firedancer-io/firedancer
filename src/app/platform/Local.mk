# Protocol-agnostic fdctl code. Depends on ballet, util.
$(call make-lib,fdctl_platform)

# Config parsing util

$(call add-hdrs,fd_config_extract.h)
$(call add-objs,fd_config_extract,fdctl_platform)

# System utils

$(call add-hdrs,fd_cap_chk.h)
ifdef FD_HAS_LINUX
$(call add-objs,fd_cap_chk,fdctl_platform)
endif

$(call add-hdrs,fd_sys_util.h)
$(call add-objs,fd_sys_util,fdctl_platform)

ifdef FD_HAS_LINUX
$(call add-hdrs,fd_net_util.h)
$(call add-objs,fd_net_util,fdctl_platform)
endif

$(call add-hdrs,fd_file_util.h)
$(call add-objs,fd_file_util,fdctl_platform)
