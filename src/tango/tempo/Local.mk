$(call add-hdrs,fd_tempo.h)
$(call add-objs,fd_tempo,fd_tango)
$(call make-unit-test,test_tempo,test_tempo,fd_tango fd_util)
$(call run-unit-test,test_tempo)
$(call make-unit-test,bench_tempo_calib,bench_tempo_calib,fd_tango fd_util)

