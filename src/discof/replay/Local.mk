$(call add-hdrs,fd_execrp.h)
$(call add-objs,fd_rdisp,fd_discof)
$(call make-unit-test,test_rdisp,test_rdisp,fd_discof fd_ballet fd_tango fd_util)
$(call run-unit-test,test_rdisp)
$(call add-objs,fd_sched,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_sched,test_sched,fd_discof fd_choreo fd_disco fd_flamenco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_sched)
$(call make-fuzz-test,fuzz_sched_rdisp,fuzz_sched_rdisp,fd_discof fd_choreo fd_disco fd_flamenco fd_ballet fd_tango fd_util)
endif

ifdef FD_HAS_HOSTED
$(call add-objs,fd_replay_tile,fd_discof)
$(call make-unit-test,test_replay_tile,test_replay_tile,fd_discof fd_choreo fd_disco fd_flamenco fd_vinyl fd_tango fd_ballet fd_util)
$(call add-hdrs,fd_vote_tracker.h)
$(call add-objs,fd_vote_tracker,fd_discof)
endif
