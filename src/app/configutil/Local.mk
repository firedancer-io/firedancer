ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_INT128

$(call make-lib,fd_configutil)

$(call add-hdrs,fd_file_util.h)
$(call add-hdrs,fd_config_parse.h)

$(call add-objs,fd_file_util,fd_configutil)
$(call add-objs,fd_config_parse,fd_configutil)

endif
endif
endif
