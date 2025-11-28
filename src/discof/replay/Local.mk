$(call add-hdrs,fd_exec.h)
$(call add-objs,fd_rdisp,fd_discof)
$(call make-unit-test,test_rdisp,test_rdisp,fd_discof fd_ballet fd_tango fd_util)
$(call run-unit-test,test_rdisp,)
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_sched,fd_discof)
endif
ifdef FD_HAS_ZSTD # required to load snapshot
$(call add-objs,fd_replay_tile,fd_discof)

$(call add-hdrs,fd_vote_tracker.h)
$(call add-objs,fd_vote_tracker,fd_discof)

else
$(warning "zstd not installed, skipping replay")
endif
