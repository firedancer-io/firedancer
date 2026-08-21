$(call add-hdrs,fd_execrp.h)
$(call add-hdrs,fd_block_marker.h)
$(call add-objs,fd_block_marker,fd_discof)
$(call add-hdrs,fd_footer_rewards.h)
$(call add-objs,fd_footer_rewards,fd_discof)
$(call make-unit-test,test_block_marker,test_block_marker,fd_discof fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_block_marker)
$(call add-objs,fd_rdisp,fd_discof)
$(call make-unit-test,test_rdisp,test_rdisp,fd_discof fd_ballet fd_tango fd_util)
$(call run-unit-test,test_rdisp)
$(call add-objs,fd_sched,fd_discof)
$(call make-unit-test,test_sched,test_sched,fd_discof fd_disco fd_flamenco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_sched)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_sched_rdisp,fuzz_sched_rdisp,fd_discof fd_disco fd_flamenco fd_ballet fd_tango fd_util)
endif

ifdef FD_HAS_ZSTD # required to load snapshot
$(call add-objs,fd_replay_tile,fd_discof)
$(call make-unit-test,test_replay_tile,test_replay_tile,fd_discof fd_choreo fd_disco fd_flamenco fd_vinyl fd_tango fd_ballet fd_util)
$(call add-hdrs,fd_vote_tracker.h)
$(call add-objs,fd_vote_tracker,fd_discof)
else
$(warning "zstd not installed, skipping replay")
endif
