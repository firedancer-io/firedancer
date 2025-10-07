$(call add-hdrs,fd_racesan_base.h fd_racesan.h)
$(call add-objs,fd_racesan,fd_util)

$(call add-hdrs,fd_racesan_async.h)
$(call add-objs,fd_racesan_async,fd_util)

$(call add-objs,fd_racesan_weave,fd_util)

$(call make-unit-test,test_racesan,test_racesan,fd_util)
