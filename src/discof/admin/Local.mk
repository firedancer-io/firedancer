$(call add-hdrs,fd_identity_transition.h)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_adminctl fd_admin_tile,fd_discof)
$(call make-unit-test,test_admin_tile,test_admin_tile,fd_discof fd_choreo fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_admin_tile)
$(call make-unit-test,test_identity_transition,test_identity_transition,fd_util)
$(call run-unit-test,test_identity_transition)
$(call make-unit-test,bench_identity_transition,bench_identity_transition,fd_util)
endif
