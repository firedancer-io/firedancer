$(call make-lib,fd_groove)
$(call add-hdrs,fd_groove_base.h fd_groove_meta.h fd_groove_volume.h fd_groove_data.h fd_groove.h)
$(call add-objs,fd_groove_base fd_groove_meta fd_groove_volume fd_groove_data fd_groove_data_szc_cfg,fd_groove)
$(call make-unit-test,test_groove_base,test_groove_base,fd_groove fd_util)
$(call make-unit-test,test_groove_meta,test_groove_meta,fd_groove fd_util)
$(call run-unit-test,test_groove_base)
$(call run-unit-test,test_groove_meta)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_groove_volume,test_groove_volume,fd_groove fd_util)
$(call make-unit-test,test_groove_data,test_groove_data,fd_groove fd_util)
$(call run-unit-test,test_groove_volume)
$(call run-unit-test,test_groove_data)
endif
