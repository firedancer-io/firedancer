ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_racesan_base.h fd_racesan.h)
$(call add-hdrs,fd_racesan_async.h)

# fd_util when the production hooks are compiled in, else test-only
ifdef FD_HAS_RACESAN
$(call add-objs,fd_racesan fd_racesan_async fd_racesan_weave,fd_util)
$(call make-unit-test,test_racesan,test_racesan,fd_util)
else
$(call add-objs,fd_racesan fd_racesan_async fd_racesan_weave,fd_util_test)
endif
endif
