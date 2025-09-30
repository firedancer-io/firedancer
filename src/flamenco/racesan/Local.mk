$(call add-hdrs,fd_racesan_base.h fd_racesan.h)
$(call add-objs,fd_racesan,fd_flamenco)

$(call add-hdrs,fd_racesan_async.h)
$(call add-objs,fd_racesan_async,fd_flamenco)

$(call make-unit-test,test_racesan,test_racesan,fd_flamenco fd_util)
