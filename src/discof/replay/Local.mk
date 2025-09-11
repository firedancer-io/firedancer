$(call add-objs,fd_rdisp,fd_discof)
$(call make-unit-test,test_rdisp,test_rdisp,fd_discof fd_ballet fd_tango fd_util)
$(call run-unit-test,test_rdisp,)
ifdef FD_HAS_INT128
$(call add-hdrs,fd_replay_notif.h)
$(call add-objs,fd_exec,fd_discof)
ifdef FD_HAS_ZSTD # required to load snapshot
$(call add-objs,fd_replay_tile,fd_discof)
else
$(warning "zstd not installed, skipping replay")
endif
endif
