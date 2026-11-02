# Protocol-agnostic application platform code. Depends on ballet, util.
$(call make-lib,fd_app_platform)

# Config parsing util

$(call add-hdrs,fd_config_extract.h)
$(call add-objs,fd_config_extract,fd_app_platform)

# System utils

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_cap_chk.h)
$(call add-objs,fd_cap_chk,fd_app_platform)

$(call add-hdrs,fd_sys_util.h)
$(call add-objs,fd_sys_util,fd_app_platform)

$(call add-hdrs,fd_net_util.h)
$(call add-objs,fd_net_util,fd_app_platform)

$(call add-hdrs,fd_file_util.h)
$(call add-objs,fd_file_util,fd_app_platform)
endif
