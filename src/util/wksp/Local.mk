$(call add-hdrs,fd_wksp.h)
$(call add-objs,fd_wksp_admin fd_wksp_user fd_wksp_helper fd_wksp_used_treap fd_wksp_free_treap fd_wksp_io,fd_util)
$(call add-objs,fd_wksp_io fd_wksp_checkpt_v1 fd_wksp_restore_v1 fd_wksp_checkpt_v2 fd_wksp_restore_v2,fd_util)
$(call make-bin,fd_wksp_ctl,fd_wksp_ctl,fd_util) # Just a stub if not HAS_HOSTED

ifdef FD_HAS_HOSTED # This tests need fd_shmem API support currently only available on hosted targets
$(call make-unit-test,test_wksp_used_treap,test_wksp_used_treap,fd_util)
$(call make-unit-test,test_wksp_free_treap,test_wksp_free_treap,fd_util)
$(call make-unit-test,test_wksp_admin,test_wksp_admin,fd_util)
$(call make-unit-test,test_wksp_user,test_wksp_user,fd_util)
$(call make-unit-test,test_wksp_helper,test_wksp_helper,fd_util)
$(call make-unit-test,test_wksp_tpool,test_wksp_tpool,fd_util)
$(call make-unit-test,test_wksp,test_wksp,fd_util)

$(call run-unit-test,test_wksp_used_treap)
$(call run-unit-test,test_wksp_free_treap)
$(call run-unit-test,test_wksp_admin)
$(call run-unit-test,test_wksp_user)
#$(call run-unit-test,test_wksp_helper) # FIXME: why was this not enabled?
$(call run-unit-test,test_wksp)

$(call add-test-scripts,test_wksp_ctl)
endif
